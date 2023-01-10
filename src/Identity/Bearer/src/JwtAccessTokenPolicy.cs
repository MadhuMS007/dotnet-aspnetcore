// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Linq;
using System.Security.Claims;
using Microsoft.Extensions.Options;

namespace Microsoft.AspNetCore.Identity;

internal class JwtTokenFormat : ITokenFormatProvider
{
    public Task<string> CreateTokenAsync(TokenInfo token)
    {
        throw new NotImplementedException();
    }

    public Task<TokenInfo?> ReadTokenAsync(string token)
    {
        throw new NotImplementedException();
    }
}

internal class GuidTokenFormat : ITokenFormatProvider
{
    public Task<string> CreateTokenAsync(TokenInfo token)
        => Task.FromResult(token.Id);

    public Task<TokenInfo?> ReadTokenAsync(string token)
        => Task.FromResult<TokenInfo?>(new TokenInfo(token, "", "", "", ""));
}

internal class RefreshTokenPolicy
{
}

internal class JwtAccessTokenPolicy : IAccessTokenPolicy
{
    private readonly IdentityBearerOptions _bearerOptions;

    public JwtAccessTokenPolicy(IOptions<IdentityBearerOptions> bearerOptions)
        => _bearerOptions = bearerOptions.Value;

    async Task<string> IAccessTokenPolicy.CreateAsync(string tokenId, string issuer, string audience, IDictionary<string, string> payload, DateTimeOffset notBefore, DateTimeOffset expires, DateTimeOffset issuedAt, string subject)
    {
        var jwtBuilder = new JwtBuilder(
            JWSAlg.HS256,
            _bearerOptions.Issuer!,
            _bearerOptions.SigningCredentials!,
            _bearerOptions.Audiences.LastOrDefault()!,
            subject,
            payload,
            notBefore,
            expires);
        jwtBuilder.IssuedAt = issuedAt;
        return await jwtBuilder.CreateJwtAsync();
    }

    Task<ClaimsPrincipal?> IAccessTokenPolicy.ValidateAsync(string accessToken, string issuer, string audience)
    {
        var reader = new JwtReader(
            JWSAlg.HS256,
            issuer,
            _bearerOptions.SigningCredentials!,
            audience);
        return reader.ValidateJwtAsync(accessToken);
    }
}
