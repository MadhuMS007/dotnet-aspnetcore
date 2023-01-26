// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace Microsoft.AspNetCore.Identity;

/// <summary>
/// Constants for encrypted JWT algorithms (JWE)
/// </summary>
public static class JWEAlg
{
    /// <summary>
    /// RSA-OAEP
    /// </summary>
    public const string RSA_OAEP = "RSA-OAEP";
}

// Symmetric key => used as CEK value, alg "dir", empty encrypted key value

/// <summary>
/// Base class for encrypted JWT implementations.
/// </summary>
internal abstract class JweAlg : IJwtAlgorithm
{
    public abstract string HeaderAlg { get; }

    public abstract string Encoding { get; }

    public Task<string> CreateJwtAsync(Jwt jwt, JsonWebKey? key)
    {
        jwt.Header = new JwtHeader(HeaderAlg);
        jwt.Header.Type = "JWT";
        jwt.Header.Headers["kid"] = key?.Kid!;
        jwt.Header.Headers["enc"] = Encoding;

        //var headerJson = JsonSerializer.Serialize(jwt.Header);

        //var encodedHeaderPayload = $"{WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(jwt.Header)))}.{WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(jwt.Payload))}";
        //var signature = ComputeSignature(encodedHeaderPayload, key);
        //return Task.FromResult($"{WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson))}.{WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(jwt.Payload))}.{signature}");
        throw new NotImplementedException();
    }

    public Task<Jwt?> ReadJwtAsync(string jwtToken, JsonWebKey? key)
    {
        throw new NotImplementedException();
    }

    public Task<bool> ValidateKeyAsync(JsonWebKey? key)
        => Task.FromResult(key != null && key.Kid != null);
}
