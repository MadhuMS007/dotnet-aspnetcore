// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Security.Claims;
using Microsoft.Extensions.Options;

namespace Microsoft.AspNetCore.Identity;

/// <summary>
/// Responsible for creating and validating access tokens.
/// </summary>
public interface IAccessTokenPolicy
{
    /// <summary>
    /// 
    /// </summary>
    /// <param name="tokenId">The token ID, a unique identifier which can be used to prevent replay.</param>
    /// <param name="issuer">The issuer for the token..</param>
    /// <param name="audience">The audience for the token.</param>
    /// <param name="payload">The claim payload for the token.</param>
    /// <param name="notBefore">Specifies when the token must not be accepted before.</param>
    /// <param name="expires">Specifies when the token expires.</param>
    /// <param name="issuedAt">Specifies when the token should be issued at.</param>
    /// <param name="subject">The subject(user) of the token.</param>
    /// <returns>The access token.</returns>
    Task<string> CreateAsync(string tokenId, string issuer, string audience, IDictionary<string, string> payload, DateTimeOffset notBefore, DateTimeOffset expires, DateTimeOffset issuedAt, string subject);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="accessToken"></param>
    /// <param name="issuer"></param>
    /// <param name="audience"></param>
    /// <returns>The ClaimsPrincipal with the claims payload of the access token when successfully validated, otherwise null.</returns>
    Task<ClaimsPrincipal?> ValidateAsync(string accessToken, string issuer, string audience);
}
