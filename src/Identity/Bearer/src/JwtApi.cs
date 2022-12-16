// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.AspNetCore.Identity;

/// <summary>
/// 
/// </summary>
public class JwtBuilder
{
    /// <summary>
    /// 
    /// </summary>
    /// <param name="issuer"></param>
    /// <param name="signingCredentials"></param>
    /// <param name="audience"></param>
    /// <param name="identity"></param>
    /// <param name="notBefore"></param>
    /// <param name="expires"></param>
    public JwtBuilder(string issuer, SigningCredentials signingCredentials, string audience, ClaimsIdentity identity, DateTimeOffset notBefore, DateTimeOffset expires)
    {
        Issuer = issuer;
        SigningCredentials = signingCredentials;
        Audience = audience;
        Identity = identity;
        NotBefore = notBefore;
        Expires = expires;
    }

    /// <summary>
    /// The Issuer for the token
    /// </summary>
    public string Issuer { get; set; }

    /// <summary>
    /// The <see cref="SigningCredentials"/> to use.
    /// </summary>
    public SigningCredentials SigningCredentials { get; set; }

    /// <summary>
    /// 
    /// </summary>
    public string Audience { get; set; }

    /// <summary>
    /// 
    /// </summary>
    public ClaimsIdentity Identity { get; set; }

    /// <summary>
    /// 
    /// </summary>
    public DateTimeOffset NotBefore { get; set; }

    /// <summary>
    /// 
    /// </summary>
    public DateTimeOffset Expires { get; set; }

    /// <summary>
    /// 
    /// </summary>
    /// <returns></returns>
    public string CreateJwt()
    {
        var handler = new JwtSecurityTokenHandler();

        var jwtToken = handler.CreateJwtSecurityToken(
            Issuer,
            Audience,
            Identity,
            NotBefore.UtcDateTime,
            Expires.UtcDateTime,
            //REVIEW: Do we want this configurable?
            issuedAt: DateTime.UtcNow,
            SigningCredentials);

        return handler.WriteToken(jwtToken);
    }
}
