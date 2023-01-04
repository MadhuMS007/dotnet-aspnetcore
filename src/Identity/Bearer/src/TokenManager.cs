// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Globalization;
using System.Linq;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Microsoft.AspNetCore.Identity;

/// <summary>
/// Provides the APIs for managing roles in a persistence store.
/// </summary>
/// <typeparam name="TUser">The type encapsulating a user.</typeparam>
public class TokenManager<TUser> : IAccessTokenValidator, IDisposable where TUser : class
{
    /// <summary>
    /// The token name used for all refresh tokens.
    /// </summary>
    public static readonly string RefreshTokenName = "Refresh";

    /// <summary>
    /// The token name used for all access tokens.
    /// </summary>
    public static readonly string AccessTokenName = "Access";

    private bool _disposed;

    private readonly IdentityBearerOptions _bearerOptions;
    private readonly IAccessTokenPolicy _accessTokenPolicy;
    private readonly ISystemClock _clock;

    /// <summary>
    /// The cancellation token used to cancel operations.
    /// </summary>
    protected virtual CancellationToken CancellationToken => CancellationToken.None;

    /// <summary>
    /// Constructs a new instance of <see cref="TokenManager{TUser}"/>.
    /// </summary>
    /// <param name="store"></param>
    /// <param name="userManager">An instance of <see cref="UserManager"/> used to retrieve users from and persist users.</param>
    /// <param name="errors">The <see cref="IdentityErrorDescriber"/> used to provider error messages.</param>
    /// <param name="logger">The logger used to log messages, warnings and errors.</param>
    /// <param name="claimsFactory">The factory to use to create claims principals for a user.</param>
    /// <param name="bearerOptions">The options which configure the bearer token such as signing key, audience, and issuer.</param>
    /// <param name="accessTokenPolicy"></param>
    /// <param name="clock"></param>
    /// <exception cref="ArgumentNullException"></exception>
    /// <exception cref="InvalidOperationException"></exception>
    public TokenManager(
        ITokenStore<IdentityToken> store,
        UserManager<TUser> userManager,
        IdentityErrorDescriber errors,
        ILogger<TokenManager<IdentityToken>> logger,
        IAccessTokenClaimsFactory<TUser> claimsFactory,
        IOptions<IdentityBearerOptions> bearerOptions,
        IAccessTokenPolicy accessTokenPolicy,
        ISystemClock clock)
    {
        Store = store ?? throw new ArgumentNullException(nameof(store));
        UserManager = userManager;
        ErrorDescriber = errors;
        PayloadFactory = claimsFactory;
        Logger = logger;
        _bearerOptions = bearerOptions.Value;
        _accessTokenPolicy = accessTokenPolicy;
        _clock = clock;

        // Move these to registered named options?
        _keyFormatProviders[JsonKeySerializer.ProviderId] = new JsonKeySerializer();
        _keyFormatProviders[Base64KeySerializer.ProviderId] = new Base64KeySerializer();
    }

    /// <summary>
    /// Gets the persistence store this instance operates over.
    /// </summary>
    /// <value>The persistence store this instance operates over.</value>
    protected internal ITokenStore<IdentityToken> Store { get; private set; }

    /// <summary>
    /// Gets the <see cref="ILogger"/> used to log messages from the manager.
    /// </summary>
    /// <value>
    /// The <see cref="ILogger"/> used to log messages from the manager.
    /// </value>
    public virtual ILogger Logger { get; set; }

    /// <summary>
    /// The <see cref="UserManager{TUser}"/> used.
    /// </summary>
    public UserManager<TUser> UserManager { get; set; }

    /// <summary>
    /// The <see cref="IUserClaimsPrincipalFactory{TUser}"/> used.
    /// </summary>
    public IAccessTokenClaimsFactory<TUser> PayloadFactory { get; set; }

    /// <summary>
    /// Gets the <see cref="IdentityErrorDescriber"/> used to provider error messages.
    /// </summary>
    /// <value>
    /// The <see cref="IdentityErrorDescriber"/> used to provider error messages.
    /// </value>
    public IdentityErrorDescriber ErrorDescriber { get; set; }

    /// <summary>
    /// Releases all resources.
    /// </summary>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Get a bearer token for the user.
    /// </summary>
    /// <param name="user">The user.</param>
    /// <returns></returns>
    public virtual async Task<string> GetAccessTokenAsync(TUser user)
    {
        // TODO: Device/SessionId needs should be passed in or set on TokenManager?

        // REVIEW: we could throw instead?
        if (user == null)
        {
            return string.Empty;
        }

        var payload = new Dictionary<string, string>();
        await PayloadFactory.BuildPayloadAsync(user, payload);
        var userName = await UserManager.GetUserNameAsync(user).ConfigureAwait(false);

        // REVIEW: Check that this logic is OK for jti claims
        var jti = Guid.NewGuid().ToString().GetHashCode().ToString("x", CultureInfo.InvariantCulture);
        return await _accessTokenPolicy.CreateAsync(jti,
            _bearerOptions.Issuer!,
            _bearerOptions.Audiences.FirstOrDefault() ?? string.Empty,
            payload,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddMinutes(30),
            DateTimeOffset.UtcNow,
            subject: userName!);
    }

    /// <summary>
    /// Given an access token, ensure its valid
    /// </summary>
    /// <param name="token">The access token to validate.</param>
    /// <returns>A claims principal for the token if its valid, null otherwise.</returns>
    public virtual async Task<ClaimsPrincipal?> ValidateAccessTokenAsync(string token)
    {
        var principal = await _accessTokenPolicy.ValidateAsync(token, _bearerOptions.Issuer!, _bearerOptions.Audiences.FirstOrDefault() ?? string.Empty);
        if (principal != null)
        {
            // TODO: Check for revocation
            return principal;
        }
        return null;
    }

    /// <summary>
    /// Get a refresh token for the user.
    /// </summary>
    /// <param name="user">The user.</param>
    /// <returns></returns>
    public virtual async Task<string> GetRefreshTokenAsync(TUser user)
    {
        var userId = await UserManager.GetUserIdAsync(user);

        var refreshToken = new IdentityToken()
        {
            UserId = userId,
            Purpose = RefreshTokenName,
            Value = Guid.NewGuid().ToString(),
            ValidUntil = DateTimeOffset.UtcNow.AddDays(1)
        };
        await Store.CreateAsync(refreshToken, CancellationToken);
        return refreshToken.Value;
    }

    /// <summary>
    /// Returns a new access and refresh token if refreshToken is valid, will also
    /// consume the refreshToken via calling Revoke on it.
    /// </summary>
    /// <param name="refreshToken"></param>
    /// <returns>(access token, refresh token) if successful, (null, null) otherwise.</returns>
    public virtual async Task<(string?, string?)> RefreshTokensAsync(string refreshToken)
    {
        // TODO: tests to write:
        // with deleted user

        var tok = await Store.FindAsync(RefreshTokenName, refreshToken, CancellationToken).ConfigureAwait(false); ;
        if (tok == null || tok.Revoked || _clock.UtcNow > tok.ValidUntil)
        {
            return (null, null);
        }

        var user = await UserManager.FindByIdAsync(tok.UserId).ConfigureAwait(false);
        if (user != null)
        {
            await RevokeRefreshAsync(user, refreshToken);
            return (await GetAccessTokenAsync(user), await GetRefreshTokenAsync(user));
        }
        return (null, null);
    }

    private readonly IDictionary<string, IIdentityKeyDataSerializer> _keyFormatProviders = new Dictionary<string, IIdentityKeyDataSerializer>();

    // TODO: move these
    internal virtual async Task AddSigningKeyAsync(string keyProvider, SigningKey key)
    {
        if (!_keyFormatProviders.ContainsKey(keyProvider))
        {
            throw new InvalidOperationException($"Unknown format {keyProvider}.");
        }
        var provider = _keyFormatProviders[keyProvider];
        var keyData = provider.Serialize(key);

        await Store.AddKeyAsync(key.Id, provider.ProviderId, provider.Format, keyData, CancellationToken);
    }

    internal virtual async Task<SigningKey?> GetSigningKeyAsync(string keyId)
    {
        var keyData = await Store.GetKeyAsync(keyId, CancellationToken);
        if (keyData == null)
        {
            return null;
        }
        if (!_keyFormatProviders.ContainsKey(keyData.ProviderId))
        {
            throw new InvalidOperationException($"Unknown format {keyData.Format}.");
        }
        var provider = _keyFormatProviders[keyData.ProviderId];
        return provider.Deserialize(keyData);
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="user">The user.</param>
    /// <param name="token">The refresh token.</param>
    /// <returns></returns>
    public virtual async Task<IdentityResult> RevokeRefreshAsync(TUser user, string token)
    {
        // TODO: this needs to go through store
        var refreshToken = await Store.FindAsync(RefreshTokenName, token, CancellationToken);
        if (refreshToken != null)
        {
            // TODO: this shouldn't use the POCO
            refreshToken.Revoked = true;
            return await Store.UpdateAsync(refreshToken, CancellationToken).ConfigureAwait(false); ;
        }
        return IdentityResult.Success;
    }

    /// <summary>
    /// Releases the unmanaged resources used by the role manager and optionally releases the managed resources.
    /// </summary>
    /// <param name="disposing">true to release both managed and unmanaged resources; false to release only unmanaged resources.</param>
    protected virtual void Dispose(bool disposing)
    {
        if (disposing && !_disposed)
        {
            //Store.Dispose();
        }
        _disposed = true;
    }

    /// <summary>
    /// Throws if this class has been disposed.
    /// </summary>
    protected void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(GetType().Name);
        }
    }

    /// <inheritdoc/>
    Task<ClaimsPrincipal?> IAccessTokenValidator.ValidateAsync(string token)
        => ValidateAccessTokenAsync(token);
}
