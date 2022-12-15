// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.AspNetCore.Identity;

/// <summary>
/// Contains extension methods to <see cref="IServiceCollection"/> for configuring identity services.
/// </summary>
public static class BearerServiceCollectionExtensions
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
        services.AddAuthentication("Identity.Bearer")
        //    .AddCookie(IdentityConstants.BearerCookieScheme)
        // Forward to the jwt for now
            .AddScheme<BearerSchemeOptions, IdentityBearerHandler>("Identity.Bearer", o => o.ForwardDefault = JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer();

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
