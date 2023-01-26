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
    private readonly TokenFormatOptions _options;
    private readonly IDataProtector? _protector;
    private const string Issuer = "identity";
    private const string Audience = "identity";

    public DefaultTokenFormat(TokenFormatOptions options, IDataProtectionProvider dp)
    {
        _options = options;

        // TODO: Should have unique protectors per token purpose and user?
        _protector = dp.CreateProtector("DefaultTokenFormat");
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
        jwtBuilder.PayloadProtector = _protector;

        return await jwtBuilder.CreateJwtAsync();
    }

    public async Task<TokenInfo?> ReadTokenAsync(string token)
    {
        var reader = new JwtReader(JWSAlg.None);
        reader.PayloadProtector = _protector;
        return await reader.ReadAsync(token);
    }
}
