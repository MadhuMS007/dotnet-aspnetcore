// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Linq;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Microsoft.AspNetCore.Identity;

internal class JwtTokenFormat : ITokenFormatProvider
{
    private readonly IdentityBearerOptions _options;
    private readonly IDataProtector? _protector;

    public JwtTokenFormat(IOptions<IdentityBearerOptions> options, IDataProtectionProvider dp)
    {
        _options = options.Value;

        if (_options.UseDataProtection)
        {
            // TODO: Should have unique protectors per token purpose and user?
            _protector = dp.CreateProtector("JwtTokenFormat");
        }
    }

    public ITokenSerializer PayloadSerializer => JsonTokenSerializer.Instance;

    public async Task<string> CreateTokenAsync(TokenInfo token)
    {
        var payloadDict = token.Payload as IDictionary<string, string>;
        if (payloadDict == null)
        {
            throw new InvalidOperationException("Expected IDictionary<string, string> token payload.");
        }

        // REVIEW: Check that using token.Id is okay for jti
        var jwtBuilder = new JwtBuilder(
            JWSAlg.HS256,
            _options.Issuer!,
            _options.SigningCredentials!,
            _options.Audiences.LastOrDefault()!,
            token.Subject,
            payloadDict,
            notBefore: DateTimeOffset.UtcNow,
            expires: DateTimeOffset.UtcNow.AddMinutes(30));
        jwtBuilder.IssuedAt = DateTimeOffset.UtcNow;
        jwtBuilder.Jti = token.Id;
        jwtBuilder.PayloadProtector = _protector;

        return await jwtBuilder.CreateJwtAsync();
    }

    public Task<TokenInfo?> ReadTokenAsync(string token)
    {
        var reader = new JwtReader(
            JWSAlg.HS256,
            _options.Issuer!,
            _options.SigningCredentials!,
            _options.Audiences);
        reader.PayloadProtector = _protector;

        return reader.ReadAsync(token);
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

    public Task<TokenInfo?> ReadTokenAsync(string token)
        => Task.FromResult<TokenInfo?>(new TokenInfo(token, "", "", "", ""));
}
