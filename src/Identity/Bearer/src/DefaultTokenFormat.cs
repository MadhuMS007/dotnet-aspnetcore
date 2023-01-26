// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;

namespace Microsoft.AspNetCore.Identity;

/// <summary>
/// 
/// </summary>
internal class DefaultTokenFormat : ITokenFormatProvider
{
    private readonly IDataProtectionProvider _dp;
    private const string Issuer = "identity";
    private const string Audience = "identity";

    public DefaultTokenFormat(IDataProtectionProvider dp)
    {
        _dp = dp;
    }

    public ITokenSerializer PayloadSerializer => JsonTokenSerializer.Instance;

    public async Task<string> CreateTokenAsync(TokenInfo token)
    {
        var payloadDict = token.Payload as IDictionary<string, string>;
        if (payloadDict == null)
        {
            throw new InvalidOperationException("Expected IDictionary<string, string> token payload.");
        }

        // We use dataprotection for the payload

        // REVIEW: Check that using token.Id is okay for jti
        var jwtBuilder = new JwtBuilder(
            JWSAlg.None,
            Issuer,
            signingKey: null,
            Audience,
            token.Subject,
            payloadDict,
            notBefore: DateTimeOffset.UtcNow,
            expires: DateTimeOffset.UtcNow.AddMinutes(30));
        jwtBuilder.IssuedAt = DateTimeOffset.UtcNow;
        jwtBuilder.Jti = token.Id;
        jwtBuilder.PayloadProtector = _dp.CreateProtector($"Token:{token.Purpose}");

        return await jwtBuilder.CreateJwtAsync();
    }

    public async Task<TokenInfo?> ReadTokenAsync(string token, string purpose)
    {
        var reader = new JwtReader(JWSAlg.None);
        reader.PayloadProtector = _dp.CreateProtector($"Token:{purpose}");
        return await reader.ReadAsync(token);
    }
}

/// <summary>
/// Used when the token id is sufficient
/// </summary>
internal class TokenIdFormat : ITokenFormatProvider
{
    public ITokenSerializer PayloadSerializer => JsonTokenSerializer.Instance;

    public Task<string> CreateTokenAsync(TokenInfo token)
        => Task.FromResult(token.Id);

    public Task<TokenInfo?> ReadTokenAsync(string token, string purpose)
        => Task.FromResult<TokenInfo?>(new TokenInfo(token, "", "", "", ""));
}
