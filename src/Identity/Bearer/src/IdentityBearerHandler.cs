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

internal sealed class IdentityBearerHandler : AuthenticationHandler<BearerSchemeOptions>
{
    internal static AuthenticateResult ValidatorNotFound = AuthenticateResult.Fail("No SecurityTokenValidator available for token.");
    private readonly IdentityBearerOptions _options;
    private readonly IAccessTokenValidator _tokenValidator;

    public IdentityBearerHandler(IOptionsMonitor<BearerSchemeOptions> options, ILoggerFactory logger,
        UrlEncoder encoder, ISystemClock clock, IOptions<IdentityBearerOptions> bearerOptions, IAccessTokenValidator tokenValidator)
        : base(options, logger, encoder, clock)
    {
        _options = bearerOptions.Value;
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
}
