// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Linq;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Microsoft.AspNetCore.Identity;

internal class JwtTokenFormat : ITokenFormatProvider
{
    private readonly IAccessTokenPolicy _accessTokenPolicy;
    private readonly IdentityBearerOptions _options;

    public JwtTokenFormat(IAccessTokenPolicy tokenPolicy, IOptions<IdentityBearerOptions> options)
    {
        _accessTokenPolicy = tokenPolicy;
        _options = options.Value;
    }

    public ITokenSerializer PayloadSerializer => JsonTokenSerizlier.Instance;

    public async Task<string> CreateTokenAsync(TokenInfo token)
    {
        var payloadDict = token.Payload as IDictionary<string, string>;
        if (payloadDict == null)
        {
            throw new InvalidOperationException("Expected IDictionary<string, string> token payload.");
        }

        // REVIEW: Check that using token.Id is okay for jti
        return await _accessTokenPolicy.CreateAsync(token.Id,
            _options.Issuer!,
            _options.Audiences.FirstOrDefault() ?? string.Empty,
            payloadDict,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddMinutes(30),
            DateTimeOffset.UtcNow,
            subject: token.Subject);
    }

    public Task<TokenInfo?> ReadTokenAsync(string token)
    {
        var reader = new JwtReader(
            JWSAlg.HS256,
            _options.Issuer!,
            _options.SigningCredentials!,
            _options.Audiences);

        return reader.ReadToken(token);
    }
}

internal class GuidTokenFormat : ITokenFormatProvider
{
    public ITokenSerializer PayloadSerializer => JsonTokenSerizlier.Instance;

    public Task<string> CreateTokenAsync(TokenInfo token)
        => Task.FromResult(token.Id);

    public Task<TokenInfo?> ReadTokenAsync(string token)
        => Task.FromResult<TokenInfo?>(new TokenInfo(token, "", "", "", ""));
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
        jwtBuilder.Jti = tokenId;
        return await jwtBuilder.CreateJwtAsync();
    }

    //Task<ClaimsPrincipal?> IAccessTokenPolicy.ValidateAsync(string accessToken, string issuer, string audience)
    //{
    //    var reader = new JwtReader(
    //        JWSAlg.HS256,
    //        issuer,
    //        _bearerOptions.SigningCredentials!,
    //        _bearerOptions.Audiences);
    //    return reader.ValidateJwtAsync(accessToken);
    //}
}
