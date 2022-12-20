// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using Microsoft.Extensions.Options;

namespace Microsoft.AspNetCore.Identity;

/// <summary>
/// Create the payload for a user's bearer token.
/// </summary>
public interface IBearerPayloadFactory<TUser> where TUser : class
{
    /// <summary>
    /// 
    /// </summary>
    /// <param name="user"></param>
    /// <returns></returns>
    Task<IDictionary<string, string>> CreatePayloadAsync(TUser user);
}

/// <summary>
/// 
/// </summary>
/// <typeparam name="TUser"></typeparam>
public class BearerPayloadFactory<TUser> : IBearerPayloadFactory<TUser> where TUser : class
{
    private readonly IdentityBearerOptions _bearerOptions;
    private UserManager<TUser> UserManager { get; set; }
    private IdentityOptions Options { get => UserManager.Options; }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="userManager"></param>
    /// <param name="bearerOptions"></param>
    /// <exception cref="InvalidOperationException"></exception>
    public BearerPayloadFactory(UserManager<TUser> userManager, IOptions<IdentityBearerOptions> bearerOptions)
    {
        UserManager = userManager;
        _bearerOptions = bearerOptions.Value;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="user"></param>
    /// <returns></returns>
    public async Task<IDictionary<string, string>> CreatePayloadAsync(TUser user)
    {
        var payload = new Dictionary<string, string>();

        // Based on UserClaimsPrincipalFactory
        //var userId = await UserManager.GetUserIdAsync(user).ConfigureAwait(false);
        var userName = await UserManager.GetUserNameAsync(user).ConfigureAwait(false);

        payload["iss"] = _bearerOptions.Issuer!;
        payload["sub"] = userName!;
        payload[ClaimTypes.NameIdentifier] = userName!;

        //var id = new ClaimsIdentity(IdentityConstants.BearerScheme); // REVIEW: Used to match Application scheme
            //Options.ClaimsIdentity.UserNameClaimType,
            //Options.ClaimsIdentity.RoleClaimType);
        //id.AddClaim(new Claim(Options.ClaimsIdentity.UserIdClaimType, userId));
        //id.AddClaim(new Claim(Options.ClaimsIdentity.UserNameClaimType, userName!));
//        id.AddClaim(new Claim(JwtRegisteredClaimNames.Sub, userName!));
        if (UserManager.SupportsUserEmail)
        {
            var email = await UserManager.GetEmailAsync(user).ConfigureAwait(false);
            if (!string.IsNullOrEmpty(email))
            {
                payload["email"] = email;
            }
        }
        if (UserManager.SupportsUserSecurityStamp)
        {
            payload[Options.ClaimsIdentity.SecurityStampClaimType] =
                await UserManager.GetSecurityStampAsync(user).ConfigureAwait(false);
        }
        if (UserManager.SupportsUserClaim)
        {
            var claims = await UserManager.GetClaimsAsync(user).ConfigureAwait(false);
            foreach (var claim in claims)
            {
                payload[claim.Type] = claim.Value;
            }
        }

        // REVIEW: Check that this logic is OK for jti claims
        var jti = Guid.NewGuid().ToString().GetHashCode().ToString("x", CultureInfo.InvariantCulture);
        payload[JwtRegisteredClaimNames.Jti] = jti;

        // REVIEW: why more than one aud?
        payload["aud"] = _bearerOptions.Audiences.Last().Value;
        return payload;
    }
}
