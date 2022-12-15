// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.IdentityModel.Tokens.Jwt;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Microsoft.AspNetCore.Identity;

/// <summary>
/// Provides the APIs for managing roles in a persistence store.
/// </summary>
/// <typeparam name="TUser">The type encapsulating a user.</typeparam>
public class TokenManager<TUser> : IDisposable where TUser : class
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

    /// <summary>
    /// The cancellation token used to cancel operations.
    /// </summary>
    protected virtual CancellationToken CancellationToken => CancellationToken.None;

    /// <summary>
    /// Constructs a new instance of <see cref="TokenManager{TUser}"/>.
    /// </summary>
    /// <param name="userManager">An instance of <see cref="UserManager"/> used to retrieve users from and persist users.</param>
    /// <param name="errors">The <see cref="IdentityErrorDescriber"/> used to provider error messages.</param>
    /// <param name="logger">The logger used to log messages, warnings and errors.</param>
    /// <param name="claimsFactory">The factory to use to create claims principals for a user.</param>
    /// <param name="bearerOptions">The options which configure the bearer token such as signing key, audience, and issuer.</param>
    /// <exception cref="ArgumentNullException"></exception>
    /// <exception cref="InvalidOperationException"></exception>
    public TokenManager(
//        ITokenStore<IdentityToken> store,
        UserManager<TUser> userManager,
        IdentityErrorDescriber errors,
        ILogger<TokenManager<IdentityToken>> logger,
        IBearerUserClaimsFactory<TUser> claimsFactory,
        IOptions<IdentityBearerOptions> bearerOptions)
    {
        //Store = store ?? throw new ArgumentNullException(nameof(store));
        UserManager = userManager;
        ErrorDescriber = errors;
        ClaimsFactory = claimsFactory;
        Logger = logger;
        _bearerOptions = bearerOptions.Value;
    }

    /*
    /// <summary>
    /// Gets the persistence store this instance operates over.
    /// </summary>
    /// <value>The persistence store this instance operates over.</value>
    protected ITokenStore<IdentityToken> Store { get; private set; }
    */

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
    public IBearerUserClaimsFactory<TUser> ClaimsFactory { get; set; }

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
    public virtual async Task<string> GetBearerAsync(TUser user)
    {
        // REVIEW: we could throw instead?
        if (user == null)
        {
            return string.Empty;
        }

        var identity = await ClaimsFactory.CreateIdentityAsync(user);

        var handler = new JwtSecurityTokenHandler();

        var jwtToken = handler.CreateJwtSecurityToken(
            _bearerOptions.Issuer,
            audience: null,
            identity,
            notBefore: DateTime.UtcNow,
            expires: DateTime.UtcNow.AddMinutes(30),
            issuedAt: DateTime.UtcNow,
            _bearerOptions.SigningCredentials);

        return handler.WriteToken(jwtToken);
    }

    /*
    /// <summary>
    /// Get a refresh token for the user.
    /// </summary>
    /// <param name="user">The user.</param>
    /// <returns></returns>
    public virtual async Task<IdentityToken> GetRefreshAsync(TUser user)
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
        return refreshToken;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="token"></param>
    /// <returns></returns>
    public virtual ClaimsPrincipal? ValidateAccessAsync(string token)
    {
        return null;
    }

    /// <summary>
    /// Returns the user given a valid (non expired) refresh token.
    /// </summary>
    /// <param name="token">The refresh token.</param>
    /// <returns></returns>
    public virtual async Task<TUser?> FindByRefreshAsync(string token)
    {
        var refreshToken = await Store.FindAsync(RefreshTokenName, token, CancellationToken).ConfigureAwait(false); ;
        if (refreshToken != null)
        {
            return await UserManager.FindByIdAsync(refreshToken.UserId).ConfigureAwait(false); ;
        }
        return null;
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
            refreshToken.Revoked = true;
            return await Store.UpdateAsync(refreshToken, CancellationToken).ConfigureAwait(false); ;
        }
        return IdentityResult.Success;
    }
    */
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
}
