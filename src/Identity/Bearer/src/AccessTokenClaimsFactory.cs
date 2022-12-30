// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Security.Claims;
using Microsoft.Extensions.Options;

namespace Microsoft.AspNetCore.Identity;

/// <summary>
/// Create the payload for a user's bearer token.
/// </summary>
public interface IAccessTokenClaimsFactory<TUser> where TUser : class
{
    /// <summary>
    /// 
    /// </summary>
    /// <param name="user"></param>
    /// <param name="payload">The payload to add to</param>
    /// <returns></returns>
    Task BuildPayloadAsync(TUser user, IDictionary<string, string> payload);
}

/// <summary>
/// 
/// </summary>
/// <typeparam name="TUser"></typeparam>
internal sealed class AccessTokenClaimsFactory<TUser> : IAccessTokenClaimsFactory<TUser> where TUser : class
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
    public AccessTokenClaimsFactory(UserManager<TUser> userManager, IOptions<IdentityBearerOptions> bearerOptions)
    {
        UserManager = userManager;
        _bearerOptions = bearerOptions.Value;
    }

    public async Task BuildPayloadAsync(TUser user, IDictionary<string, string> payload)
    {
        // Based on UserClaimsPrincipalFactory
        //var userId = await UserManager.GetUserIdAsync(user).ConfigureAwait(false);
        var userName = await UserManager.GetUserNameAsync(user).ConfigureAwait(false);
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

        // REVIEW: why more than one aud?
        //payload["aud"] = _bearerOptions.Audiences.LastOrDefault()!;
    }
}
