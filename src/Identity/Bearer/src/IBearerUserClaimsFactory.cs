// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Globalization;
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
    /// <param name="jwtBuilder"></param>
    /// <returns></returns>
    Task BuildPayloadAsync(TUser user, JwtBuilder jwtBuilder);
}

/// <summary>
/// 
/// </summary>
/// <typeparam name="TUser"></typeparam>
internal sealed class BearerPayloadFactory<TUser> : IBearerPayloadFactory<TUser> where TUser : class
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

    public async Task BuildPayloadAsync(TUser user, JwtBuilder jwtBuilder)
    {
        var payload = jwtBuilder.Payload;

        // Based on UserClaimsPrincipalFactory
        //var userId = await UserManager.GetUserIdAsync(user).ConfigureAwait(false);
        var userName = await UserManager.GetUserNameAsync(user).ConfigureAwait(false);
        jwtBuilder.Subject = userName!;
        payload[ClaimTypes.NameIdentifier] = userName!;

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
        //payload[JwtRegisteredClaimNames.Jti] = jti;
        jwtBuilder.Jti = Guid.NewGuid().ToString().GetHashCode().ToString("x", CultureInfo.InvariantCulture);

        // REVIEW: why more than one aud?
        //payload["aud"] = _bearerOptions.Audiences.LastOrDefault()!;
    }
}
