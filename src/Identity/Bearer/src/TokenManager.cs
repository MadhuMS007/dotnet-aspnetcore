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
/// <typeparam name="TToken">The type encapsulating a token.</typeparam>
public class TokenManager<TUser, TToken> : IAccessTokenValidator, IDisposable
    where TUser : class
    where TToken : class
{
    private readonly IdentityBearerOptions _bearerOptions;
    private readonly IAccessTokenPolicy _accessTokenPolicy;
    private readonly ISystemClock _clock;
    private bool _disposed;

    /// <summary>
    /// The cancellation token used to cancel operations.
    /// </summary>
    protected virtual CancellationToken CancellationToken => CancellationToken.None;

    /// <summary>
    /// Constructs a new instance of <see cref="TokenManager{TUser,TToken}"/>.
    /// </summary>
    /// <param name="identityOptions">The options which configure the identity system.</param>
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
        IOptions<IdentityOptions> identityOptions,
        ITokenStore<TToken> store,
        UserManager<TUser> userManager,
        IdentityErrorDescriber errors,
        ILogger<TokenManager<TUser,TToken>> logger,
        IAccessTokenClaimsFactory<TUser> claimsFactory,
        IOptions<IdentityBearerOptions> bearerOptions,
        IAccessTokenPolicy accessTokenPolicy,
        ISystemClock clock)
    {
        Options = identityOptions.Value.TokenManager;
        Store = store ?? throw new ArgumentNullException(nameof(store));
        UserManager = userManager;
        ErrorDescriber = errors;
        PayloadFactory = claimsFactory;
        Logger = logger;
        _bearerOptions = bearerOptions.Value;
        _accessTokenPolicy = accessTokenPolicy;
        _clock = clock;

        // TODO: Move these to registered named options?
        _keyFormatProviders[JsonKeySerializer.ProviderId] = new JsonKeySerializer();
        _keyFormatProviders[Base64KeySerializer.ProviderId] = new Base64KeySerializer();

        Options.FormatProviderMap[TokenFormat.JWT] = new JwtTokenFormat();
        Options.FormatProviderMap[TokenFormat.Single] = new GuidTokenFormat();

        Options.PurposeFormatMap[TokenPurpose.RefreshToken] = TokenFormat.Single;
        Options.PurposeFormatMap[TokenPurpose.AccessToken] = TokenFormat.JWT;
    }

    /// <summary>
    /// Gets the persistence store this instance operates over.
    /// </summary>
    /// <value>The persistence store this instance operates over.</value>
    protected internal ITokenStore<TToken> Store { get; }

    /// <summary>
    /// Gets the <see cref="ILogger"/> used to log messages from the manager.
    /// </summary>
    /// <value>
    /// The <see cref="ILogger"/> used to log messages from the manager.
    /// </value>
    public virtual ILogger Logger { get; set; }

    /// <summary>
    /// The <see cref="TokenManagerOptions"/>.
    /// </summary>
    public TokenManagerOptions Options { get; set; }

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
    /// Create a new token instance with the specified token info. This should not be stored
    /// in the token store yet.
    /// </summary>
    /// <param name="info">The <see cref="TokenInfo"/> for the token.</param>
    /// <returns></returns>
    public virtual Task<TToken> NewAsync(TokenInfo info)
        => Store.NewAsync(info, CancellationToken);

    private (string, ITokenFormatProvider) GetFormatProvider(string tokenPurpose)
    {
        // TODO: someone should be validating these
        var format = Options.PurposeFormatMap[tokenPurpose];
        if (!Options.FormatProviderMap.TryGetValue(format, out var provider))
        {
            throw new InvalidOperationException($"Could not find token format provider {format} registered for purpose: {tokenPurpose}.");
        }
        return (format, provider);
    }

    /// <summary>
    /// Get a refresh token for the user.
    /// </summary>
    /// <param name="user">The user.</param>
    /// <returns></returns>
    public virtual async Task<string> GetRefreshTokenAsync(TUser user)
    {
        (var format, var provider) = GetFormatProvider(TokenPurpose.RefreshToken);

        // Build the raw token and payload
        var userId = await UserManager.GetUserIdAsync(user);

        // Store the token metadata, refresh tokens don't need additional data
        // so no payload is specified for the token info.
        var info = new TokenInfo(Guid.NewGuid().ToString(),
            format, userId, TokenPurpose.RefreshToken, TokenStatus.Active)
        {
            Expiration = DateTimeOffset.UtcNow.AddDays(1)
        };
        var token = await Store.NewAsync(info, CancellationToken).ConfigureAwait(false);
        await Store.CreateAsync(token, CancellationToken);
        return await provider.CreateTokenAsync(info);
    }

    /// <summary>
    /// Check if the token status is valid. Defaults to only active token status.
    /// </summary>
    /// <param name="status">The token status.</param>
    /// <returns>true if the token is should be allowed.</returns>
    protected virtual bool CheckTokenStatus(string status)
        => status == TokenStatus.Active;

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
        (var _, var provider) = GetFormatProvider(TokenPurpose.RefreshToken);

        var tokenInfo = await provider.ReadTokenAsync(refreshToken);
        if (tokenInfo == null)
        {
            return (null, null);
        }

        var tok = await Store.FindByIdAsync(tokenInfo.Id, CancellationToken).ConfigureAwait(false);
        if (tok == null)
        {
            return (null, null);
        }

        var status = await Store.GetStatusAsync(tok, CancellationToken).ConfigureAwait(false);
        if (!CheckTokenStatus(status))
        {
            return (null, null);
        }

        var expires = await Store.GetExpirationAsync(tok, CancellationToken).ConfigureAwait(false);
        if (expires < _clock.UtcNow)
        {
            return (null, null);
        }

        var userId = await Store.GetSubjectAsync(tok, CancellationToken).ConfigureAwait(false);
        var user = await UserManager.FindByIdAsync(userId).ConfigureAwait(false);
        if (user != null)
        {
            // Mark the refresh token as used
            await Store.SetStatusAsync(tok, TokenStatus.Inactive, CancellationToken).ConfigureAwait(false);
            await Store.UpdateAsync(tok, CancellationToken).ConfigureAwait(false);
            return (await GetAccessTokenAsync(user), await GetRefreshTokenAsync(user));
        }
        return (null, null);
    }

    private readonly IDictionary<string, IIdentityKeyDataSerializer> _keyFormatProviders = new Dictionary<string, IIdentityKeyDataSerializer>();

    // TODO: move these
    internal virtual async Task AddSigningKeyAsync(string keyProvider, SigningKeyInfo key)
    {
        if (!_keyFormatProviders.ContainsKey(keyProvider))
        {
            throw new InvalidOperationException($"Unknown format {keyProvider}.");
        }
        var provider = _keyFormatProviders[keyProvider];
        var keyData = provider.Serialize(key);

        await ((IKeyStore)Store).AddAsync(key.Id, provider.ProviderId, provider.Format, keyData, CancellationToken);
    }

    internal virtual async Task<SigningKeyInfo?> GetSigningKeyAsync(string keyId)
    {
        var keyData = await ((IKeyStore)Store).FindByIdAsync(keyId, CancellationToken);
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
        (var _, var provider) = GetFormatProvider(TokenPurpose.RefreshToken);

        var tokenInfo = await provider.ReadTokenAsync(token);
        if (tokenInfo == null)
        {
            return IdentityResult.Success;
        }

        var tok = await Store.FindByIdAsync(tokenInfo.Id, CancellationToken).ConfigureAwait(false);
        if (tok != null)
        {
            await Store.SetStatusAsync(tok, TokenStatus.Revoked, CancellationToken);
            return await Store.UpdateAsync(tok, CancellationToken).ConfigureAwait(false); ;
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
