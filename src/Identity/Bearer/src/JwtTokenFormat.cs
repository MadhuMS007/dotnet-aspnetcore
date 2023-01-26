// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Microsoft.Extensions.DependencyInjection;

namespace Microsoft.AspNetCore.Identity;

//internal class JwtTokenFormat : ITokenFormatProvider
//{
//    private readonly TokenFormatOptions _options;
//    private readonly IDataProtector? _protector;
//    private readonly KeyRingManager _keyRings;
//    private readonly string _issuer;
//    private readonly string _audience;

//    public JwtTokenFormat(KeyRingManager keyRings, TokenFormatOptions options, IDataProtectionProvider dp, string issuer, string audience)
//    {
//        _keyRings = keyRings;
//        _options = options;
//        _issuer = issuer;
//        _audience = audience;

//        if (_options.UseDataProtection)
//        {
//            // TODO: Should have unique protectors per token purpose and user?
//            _protector = dp.CreateProtector("JwtTokenFormat");
//        }
//        _issuer = issuer;
//    }

//    public ITokenSerializer PayloadSerializer => JsonTokenSerializer.Instance;

//    public async Task<string> CreateTokenAsync(TokenInfo token)
//    {
//        var payloadDict = token.Payload as IDictionary<string, string>;
//        if (payloadDict == null)
//        {
//            throw new InvalidOperationException("Expected IDictionary<string, string> token payload.");
//        }

//        // We use dataprotection for the payload

//        // REVIEW: Check that using token.Id is okay for jti
//        var jwtBuilder = new JwtBuilder(
//            JWSAlg.HS256,
//            _issuer,
//            jwk,
//            _audience, // TODO: audience feels weird here
//            token.Subject,
//            payloadDict,
//            notBefore: DateTimeOffset.UtcNow,
//            expires: DateTimeOffset.UtcNow.AddMinutes(30));
//        jwtBuilder.IssuedAt = DateTimeOffset.UtcNow;
//        jwtBuilder.Jti = token.Id;
//        jwtBuilder.PayloadProtector = _protector;

//        return await jwtBuilder.CreateJwtAsync();
//    }

//    public async Task<TokenInfo?> ReadTokenAsync(string token)
//    {
//        // No key ring specified would just use the default key ring
//        var keyRing = await _keyRings.GetKeyRingAsync(_options.ValidationKeyRing);
//        var key = await keyRing.GetActiveKeyAsync();

//        var jwk = new JsonWebKey("oct")
//        {
//            Alg = "HS256",
//        };
//        jwk.AdditionalData["k"] = WebEncoders.Base64UrlEncode(key.Data);

//        var reader = new JwtReader(
//            JWSAlg.HS256,
//            _issuer,
//            jwk,
//            new[] { _audience });
//        reader.PayloadProtector = _protector;

//        return await reader.ReadAsync(token);
//    }
//}

/// <summary>
/// Used when the token id is sufficient
/// </summary>
internal class TokenIdFormat : ITokenFormatProvider
{
    public ITokenSerializer PayloadSerializer => JsonTokenSerializer.Instance;

    public Task<string> CreateTokenAsync(TokenInfo token)
        => Task.FromResult(token.Id);

    public Task<TokenInfo?> ReadTokenAsync(string token)
        => Task.FromResult<TokenInfo?>(new TokenInfo(token, "", "", "", ""));
}
