// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Microsoft.AspNetCore.Identity;

internal interface IAccessTokenValidator
{
    Task<ClaimsPrincipal?> ValidateAsync(string token);
}

internal class DefaultAccessTokenValidator<TUser> : IAccessTokenValidator
    where TUser: class
{
    private readonly IUserTokenService<TUser> _tokenService;
    private readonly IAccessTokenDenyPolicy _accessTokenDenyPolicy;

    public DefaultAccessTokenValidator(IUserTokenService<TUser> tokenService, IAccessTokenDenyPolicy accessTokenDenyPolicy)
    {
        _tokenService = tokenService;
        _accessTokenDenyPolicy = accessTokenDenyPolicy;
    }

    /// <inheritdoc/>
    async Task<ClaimsPrincipal?> IAccessTokenValidator.ValidateAsync(string token)
    {
        var tokenInfo = await _tokenService.ReadAccessTokenAsync(token);
        if (tokenInfo == null)
        {
            return null;
        }

        // Check for revocation
        if (_accessTokenDenyPolicy != null && await _accessTokenDenyPolicy.IsDeniedAsync(tokenInfo.Id))
        {
            return null;
        }

        var payloadDict = tokenInfo.Payload as IDictionary<string, string>;
        if (payloadDict == null)
        {
            throw new InvalidOperationException("Expected IDictionary<string, string> token payload.");
        }

        var claimsIdentity = new ClaimsIdentity(IdentityConstants.BearerScheme);
        foreach (var key in payloadDict.Keys)
        {
            claimsIdentity.AddClaim(new Claim(key, payloadDict[key]));
        }
        return new ClaimsPrincipal(claimsIdentity);
    }
}

internal sealed class IdentityBearerHandler : AuthenticationHandler<BearerSchemeOptions>, IAuthenticationSignInHandler
{
    internal static AuthenticateResult ValidatorNotFound = AuthenticateResult.Fail("No SecurityTokenValidator available for token.");
    private readonly IAccessTokenValidator _tokenValidator;

    public IdentityBearerHandler(IOptionsMonitor<BearerSchemeOptions> options, ILoggerFactory logger,
        UrlEncoder encoder, ISystemClock clock, IAccessTokenValidator tokenValidator)
        : base(options, logger, encoder, clock)
    {
        _tokenValidator = tokenValidator;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        // Check the cookie first (could just rely on forward authenticate, consider)
        var result = await Context.AuthenticateAsync(IdentityConstants.BearerCookieScheme);
        if (result.Succeeded)
        {
            return result;
        }

        // Otherwise check for Bearer token
        string? token = null;
        var authorization = Request.Headers.Authorization.ToString();

        // If no authorization header found, nothing to process further
        if (string.IsNullOrEmpty(authorization))
        {
            return AuthenticateResult.NoResult();
        }

        if (authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            token = authorization["Bearer ".Length..].Trim();
        }

        // If no token found, no further work possible
        if (string.IsNullOrEmpty(token))
        {
            return AuthenticateResult.NoResult();
        }

        var principal = await _tokenValidator.ValidateAsync(token);
        if (principal != null)
        {
            return AuthenticateResult.Success(new AuthenticationTicket(principal, Scheme.Name));
        }
        return AuthenticateResult.NoResult();
    }

    // REVIEW: maybe this should just forward?
    public Task SignInAsync(ClaimsPrincipal user, AuthenticationProperties? properties)
        => Context.SignInAsync(IdentityConstants.BearerCookieScheme, user, properties);

    public Task SignOutAsync(AuthenticationProperties? properties)
        => Context.SignOutAsync(IdentityConstants.BearerCookieScheme, properties);
}
