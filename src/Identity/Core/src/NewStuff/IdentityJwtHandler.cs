// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Configuration.UserSecrets;
using System.Text.Json.Nodes;
using System.Text.Json;

namespace Microsoft.AspNetCore.Identity;

/// <summary>
/// 
/// </summary>
public class IdentityJwtHandler : AuthenticationHandler<IdentityJwtOptions>
{
    private readonly JwtSecurityTokenHandler _defaultHandler = new JwtSecurityTokenHandler();
    internal static AuthenticateResult ValidatorNotFound = AuthenticateResult.Fail("No SecurityTokenValidator available for token.");

    public IdentityJwtHandler(IOptionsMonitor<IdentityJwtOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock)
    {
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
        string? token = null;
        try
        {
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

            var validationParameters = Options.TokenValidationParameters.Clone();

            var newKeyMaterial = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);

            validationParameters.IssuerSigningKey = new SymmetricSecurityKey(ReadKeyAsBytes(_jwtSettings.TokenSecretKey))

            //if (_configuration != null)
            //{
            //    var issuers = new[] { _configuration.Issuer };
            //    validationParameters.ValidIssuers = validationParameters.ValidIssuers?.Concat(issuers) ?? issuers;

            //    validationParameters.IssuerSigningKeys = validationParameters.IssuerSigningKeys?.Concat(_configuration.SigningKeys)
            //        ?? _configuration.SigningKeys;
            //}

            SecurityToken? validatedToken = null;
            var validator = _defaultHandler;
            if (validator.CanReadToken(token))
            {
                ClaimsPrincipal principal;
                try
                {
                    principal = validator.ValidateToken(token, validationParameters, out validatedToken);

                    //if (Options.SaveToken)
                    //{
                    //    tokenValidatedContext.Properties.StoreTokens(new[]
                    //    {
                    //            new AuthenticationToken { Name = "access_token", Value = token }
                    //        });
                    //}

                    return AuthenticateResult.Success(new AuthenticationTicket(principal, Scheme.Name));
                }
                catch (Exception ex)
                {
                    return AuthenticateResult.Fail(ex);
                }

            }
            return ValidatorNotFound;
        }
        finally
        {
        }
    }
}
