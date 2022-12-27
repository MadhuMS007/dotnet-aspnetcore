// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Microsoft.AspNetCore.Identity;

/// <summary>
/// 
/// </summary>
internal sealed class IdentityBearerHandler : AuthenticationHandler<BearerSchemeOptions>
{
    internal static AuthenticateResult ValidatorNotFound = AuthenticateResult.Fail("No SecurityTokenValidator available for token.");
    private readonly IdentityBearerOptions _options;

    public IdentityBearerHandler(IOptionsMonitor<BearerSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock, IOptions<IdentityBearerOptions> bearerOptions) : base(options, logger, encoder, clock)
    {
        _options = bearerOptions.Value;
    }

    //public static byte[] CreateSigningKeyMaterial(string userSecretsId, string scheme, string issuer, int signingKeyLength = 32, bool reset = false)
    //{
    //    // Create signing material and save to user secrets
    //    var newKeyMaterial = System.Security.Cryptography.RandomNumberGenerator.GetBytes(signingKeyLength);
    //    //var secretsFilePath = @"C:\Users\haok\keys\identityjwt.txt";

    //    //JsonObject secrets = null;
    //    //if (File.Exists(secretsFilePath))
    //    //{
    //    //    using var secretsFileStream = new FileStream(secretsFilePath, FileMode.Open, FileAccess.Read);
    //    //    if (secretsFileStream.Length > 0)
    //    //    {
    //    //        secrets = JsonSerializer.Deserialize<JsonObject>(secretsFileStream);
    //    //    }
    //    //}

    //    //secrets ??= new JsonObject();
    //    //var signkingKeysPropertyName = GetSigningKeyPropertyName(scheme);
    //    //var shortId = Guid.NewGuid().ToString("N").Substring(0, 8);
    //    //var key = new SigningKey(shortId, issuer, Convert.ToBase64String(newKeyMaterial), signingKeyLength);

    //    //if (secrets.ContainsKey(signkingKeysPropertyName))
    //    //{
    //    //    var signingKeys = secrets[signkingKeysPropertyName].AsArray();
    //    //    if (reset)
    //    //    {
    //    //        var toRemove = signingKeys.SingleOrDefault(key => key["Issuer"].GetValue<string>() == issuer);
    //    //        signingKeys.Remove(toRemove);
    //    //    }
    //    //    signingKeys.Add(key);
    //    //}
    //    //else
    //    //{
    //    //    secrets.Add(signkingKeysPropertyName, JsonValue.Create(new[] { key }));
    //    //}

    //    //using var secretsWriteStream = new FileStream(secretsFilePath, FileMode.Create, FileAccess.Write);
    //    //JsonSerializer.Serialize(secretsWriteStream, secrets);

    //    return newKeyMaterial;
    //}

    ///
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
            token = authorization.Substring("Bearer ".Length).Trim();
        }

        // If no token found, no further work possible
        if (string.IsNullOrEmpty(token))
        {
            return AuthenticateResult.NoResult();
        }

        // The token should be the raw payload right now
        var payload = await JwtBuilder.ReadJwtAsync(token, JWSAlg.HS256, _options.SigningCredentials);
        if (payload != null)
        {
            var claimsIdentity = new ClaimsIdentity(Scheme.Name);
            foreach (var key in payload.Keys)
            {
                claimsIdentity.AddClaim(new Claim(key, payload[key]));
            }
            return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(claimsIdentity), Scheme.Name));
        }
        return AuthenticateResult.NoResult();
    }
}
