// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.AspNetCore.Identity;

/// <summary>
/// Contains extension methods to <see cref="IServiceCollection"/> for configuring identity services.
/// </summary>
public static class IdentityJwtServiceCollectionExtensions
{
    /// <summary>
    /// 
    /// </summary>
    /// <typeparam name="TUser"></typeparam>
    /// <param name="services"></param>
    /// <returns></returns>
    public static IdentityBuilder AddDefaultIdentityBearer<TUser>(this IServiceCollection services)
        where TUser : class
    => services.AddDefaultIdentityBearer<TUser>(_ => { });

    /// <summary>
    /// 
    /// </summary>
    /// <typeparam name="TUser"></typeparam>
    /// <param name="services"></param>
    /// <param name="setupAction"></param>
    /// <returns></returns>
    public static IdentityBuilder AddDefaultIdentityBearer<TUser>(this IServiceCollection services,
        Action<IdentityOptions> setupAction)
        where TUser : class
    {
        //services.AddAuthentication(IdentityConstants.BearerScheme)
        //    .AddCookie(IdentityConstants.BearerCookieScheme)
        //    .AddScheme<BearerSchemeOptions, IdentityBearerHandler>(IdentityConstants.BearerScheme, configureOptions: null);

        services.AddOptions<IdentityBearerOptions>().Configure<IAuthenticationConfigurationProvider>((o, cp) =>
        {
            // We're reading the authentication configuration for the Bearer scheme
            var bearerSection = cp.GetSchemeConfiguration(IdentityConstants.BearerScheme);

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

            o.Issuer = bearerSection["ValidIssuer"] ?? throw new InvalidOperationException("Issuer is not specified");
            var signingKeyBase64 = section["Value"] ?? throw new InvalidOperationException("Signing key is not specified");

            var signingKeyBytes = Convert.FromBase64String(signingKeyBase64);

            o.SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(signingKeyBytes),
                    SecurityAlgorithms.HmacSha256Signature);

            o.Audiences = (bearerSection.GetSection("ValidAudiences").GetChildren()
                        .Where(s => !string.IsNullOrEmpty(s.Value))
                        .Select(s => new Claim(JwtRegisteredClaimNames.Aud, s.Value!))
                        .ToList());
        });

        services.TryAddScoped<TokenManager<TUser>>();
        services.TryAddScoped<IBearerUserClaimsFactory<TUser>, BearerUserClaimsFactory<TUser>>();
        return services.AddIdentityCore<TUser>(setupAction);
    }
}

/// <summary>
/// 
/// </summary>
internal sealed class IdentityBearerHandler : AuthenticationHandler<BearerSchemeOptions>
{
    private readonly JwtSecurityTokenHandler _defaultHandler = new JwtSecurityTokenHandler();
    internal static AuthenticateResult ValidatorNotFound = AuthenticateResult.Fail("No SecurityTokenValidator available for token.");

    public IdentityBearerHandler(IOptionsMonitor<BearerSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock)
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
        // Check the cookie first (could just rely on forward authenticate, consider)
        var result = await Context.AuthenticateAsync(IdentityConstants.BearerCookieScheme);
        if (result.Succeeded)
        {
            return result;
        }

        // Otherwise check for Bearer token
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

            // delete
            await Task.Delay(1);

            var validationParameters = Options.TokenValidationParameters.Clone();

            //var newKeyMaterial = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);

            //validationParameters.IssuerSigningKey = new SymmetricSecurityKey(ReadKeyAsBytes(_jwtSettings.TokenSecretKey))

            //if (_configuration != null)
            //{
            //    var issuers = new[] { _configuration.Issuer };
            //    validationParameters.ValidIssuers = validationParameters.ValidIssuers?.Concat(issuers) ?? issuers;

            //    validationParameters.IssuerSigningKeys = validationParameters.IssuerSigningKeys?.Concat(_configuration.SigningKeys)
            //        ?? _configuration.SigningKeys;
            //}

            SecurityToken? validatedToken;
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
