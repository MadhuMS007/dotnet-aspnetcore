// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

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
    private readonly string _issuer;
    private readonly SigningCredentials _jwtSigningCredentials;
    private readonly Claim[] _audiences;

    /// <summary>
    /// The cancellation token used to cancel operations.
    /// </summary>
    protected virtual CancellationToken CancellationToken => CancellationToken.None;

    /// <summary>
    /// Constructs a new instance of <see cref="TokenManager{TUser}"/>.
    /// </summary>
    /// <param name="store">The persistence store the manager will operate over.</param>
    /// <param name="userManager">An instance of <see cref="UserManager"/> used to retrieve users from and persist users.</param>
    /// <param name="errors">The <see cref="IdentityErrorDescriber"/> used to provider error messages.</param>
    /// <param name="logger">The logger used to log messages, warnings and errors.</param>
    /// <param name="claimsFactory">The factory to use to create claims principals for a user.</param>
    /// <param name="authenticationConfigurationProvider">Used to access the authentication configuration section.</param>
    /// <exception cref="ArgumentNullException"></exception>
    /// <exception cref="InvalidOperationException"></exception>
    public TokenManager(ITokenStore<IdentityToken> store,
        UserManager<TUser> userManager,
        IdentityErrorDescriber errors,
        ILogger<TokenManager<IdentityToken>> logger,
        IUserClaimsPrincipalFactory<IdentityToken> claimsFactory,
        IAuthenticationConfigurationProvider authenticationConfigurationProvider)
    {
        if (store == null)
        {
            throw new ArgumentNullException(nameof(store));
        }
        Store = store;
        UserManager = userManager;
        ErrorDescriber = errors;
        ClaimsFactory = claimsFactory;
        Logger = logger;

        // We're reading the authentication configuration for the Bearer scheme
        var bearerSection = authenticationConfigurationProvider.GetSchemeConfiguration(IdentityConstants.BearerScheme);

        // An example of what the expected schema looks like
        // "Authentication": {
        //     "Schemes": {
        //       "Bearer": {
        //         "ValidAudiences": [ ],
        //         "ValidIssuer": "",
        //         "SigningKeys": [ { "Issuer": .., "Value": base64Key, "Length": 32 } ]
        //       }
        //     }
        //   }

        var section = bearerSection.GetSection("SigningKeys:0");

        _issuer = bearerSection["ValidIssuer"] ?? throw new InvalidOperationException("Issuer is not specified");
        var signingKeyBase64 = section["Value"] ?? throw new InvalidOperationException("Signing key is not specified");

        var signingKeyBytes = Convert.FromBase64String(signingKeyBase64);

        _jwtSigningCredentials = new SigningCredentials(new SymmetricSecurityKey(signingKeyBytes),
                SecurityAlgorithms.HmacSha256Signature);

        _audiences = bearerSection.GetSection("ValidAudiences").GetChildren()
                    .Where(s => !string.IsNullOrEmpty(s.Value))
                    .Select(s => new Claim(JwtRegisteredClaimNames.Aud, s.Value!))
                    .ToArray();
    }

    /// <summary>
    /// Gets the persistence store this instance operates over.
    /// </summary>
    /// <value>The persistence store this instance operates over.</value>
    protected ITokenStore<IdentityToken> Store { get; private set; }

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
    public IUserClaimsPrincipalFactory<IdentityToken> ClaimsFactory { get; set; }

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
    public virtual string GetBearerAsync(TUser user)
    {
        // TODO: Get the claims principal for the user
        var identity = new ClaimsIdentity(IdentityConstants.BearerScheme);

        identity.AddClaim(new Claim(JwtRegisteredClaimNames.Sub, "<username>"));

        // REVIEW: Check that this logic is OK for jti claims
        var id = Guid.NewGuid().ToString().GetHashCode().ToString("x", CultureInfo.InvariantCulture);

        identity.AddClaim(new Claim(JwtRegisteredClaimNames.Jti, id));

        //// Check if user is Admin somehow
        //if (isAdmin)
        //{
        //    identity.AddClaim(new Claim(ClaimTypes.Role, "admin"));
        //}

        identity.AddClaims(_audiences);

        var handler = new JwtSecurityTokenHandler();

        var jwtToken = handler.CreateJwtSecurityToken(
            _issuer,
            audience: null,
            identity,
            notBefore: DateTime.UtcNow,
            expires: DateTime.UtcNow.AddMinutes(30),
            issuedAt: DateTime.UtcNow,
            _jwtSigningCredentials);

        return handler.WriteToken(jwtToken);
    }

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

    /// <summary>
    /// Releases the unmanaged resources used by the role manager and optionally releases the managed resources.
    /// </summary>
    /// <param name="disposing">true to release both managed and unmanaged resources; false to release only unmanaged resources.</param>
    protected virtual void Dispose(bool disposing)
    {
        if (disposing && !_disposed)
        {
            Store.Dispose();
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
