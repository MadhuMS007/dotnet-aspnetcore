// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using Microsoft.Extensions.Options;

namespace Microsoft.AspNetCore.Identity;

/// <summary>
/// Create a <see cref="ClaimsIdentity"/> for a user.
/// </summary>
public interface IBearerUserClaimsFactory<TUser> where TUser : class
{
    /// <summary>
    /// 
    /// </summary>
    /// <param name="user"></param>
    /// <returns></returns>
    Task<ClaimsIdentity> CreateIdentityAsync(TUser user);
}

/// <summary>
/// 
/// </summary>
/// <typeparam name="TUser"></typeparam>
public class BearerUserClaimsFactory<TUser> : IBearerUserClaimsFactory<TUser> where TUser : class
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
    public BearerUserClaimsFactory(UserManager<TUser> userManager, IOptions<IdentityBearerOptions> bearerOptions)
    {
        UserManager = userManager;
        _bearerOptions = bearerOptions.Value;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="user"></param>
    /// <returns></returns>
    public async Task<ClaimsIdentity> CreateIdentityAsync(TUser user)
    {
        // Based on UserClaimsPrincipalFactory
        var userId = await UserManager.GetUserIdAsync(user).ConfigureAwait(false);
        var userName = await UserManager.GetUserNameAsync(user).ConfigureAwait(false);
        var id = new ClaimsIdentity(IdentityConstants.BearerScheme); // REVIEW: Used to match Application scheme
            //Options.ClaimsIdentity.UserNameClaimType,
            //Options.ClaimsIdentity.RoleClaimType);
        //id.AddClaim(new Claim(Options.ClaimsIdentity.UserIdClaimType, userId));
        //id.AddClaim(new Claim(Options.ClaimsIdentity.UserNameClaimType, userName!));
        id.AddClaim(new Claim(JwtRegisteredClaimNames.Sub, userName!));
        if (UserManager.SupportsUserEmail)
        {
            var email = await UserManager.GetEmailAsync(user).ConfigureAwait(false);
            if (!string.IsNullOrEmpty(email))
            {
                id.AddClaim(new Claim(Options.ClaimsIdentity.EmailClaimType, email));
            }
        }
        if (UserManager.SupportsUserSecurityStamp)
        {
            id.AddClaim(new Claim(Options.ClaimsIdentity.SecurityStampClaimType,
                await UserManager.GetSecurityStampAsync(user).ConfigureAwait(false)));
        }
        if (UserManager.SupportsUserClaim)
        {
            id.AddClaims(await UserManager.GetClaimsAsync(user).ConfigureAwait(false));
        }

        // REVIEW: Check that this logic is OK for jti claims
        var jti = Guid.NewGuid().ToString().GetHashCode().ToString("x", CultureInfo.InvariantCulture);
        id.AddClaim(new Claim(JwtRegisteredClaimNames.Jti, jti));

        // REVIEW: move this into the options setup instead to do it once
        var audiences = _bearerOptions.Audiences
                    .Where(s => !string.IsNullOrEmpty(s.Value))
                    .Select(s => new Claim(JwtRegisteredClaimNames.Aud, s.Value!))
                    .ToArray();
        id.AddClaims(audiences);
        return id;
    }
}
