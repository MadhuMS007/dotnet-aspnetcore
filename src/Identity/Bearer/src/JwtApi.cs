// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace Microsoft.AspNetCore.Identity;

// FormatOptions specifies Algorithm and the signing key so BCL can sign/validate
// jwtData contains both the header dictionary and the payload string
// CreateJwtAsync => BclApi.CreateJwtAsync(formatOptions, jwtData);
// ReadJwtAsync => jwtData = BclApi.ReadJwtAsync(formatOptions) // null or throw on failure

// RS256 JWT
// new JwtBuilder(JwtAlgorithm.RS256)
//      .SetSigningKey(keyString)
//      .SetPayload(claimsAsJson)

// Reference https://www.rfc-editor.org/rfc/rfc7515#section-4.1 for header paamters
// JWK header => JWK?

// JWK and JWKS (set of keys)

internal interface IJWKStore
{
    /// <summary>
    /// Return all of the secrets in the store
    /// </summary>
    /// <returns></returns>
    Task<IEnumerable<JsonWebKey>> GetAllAsync();

    /// <summary>
    /// Adds a jwk to the store.
    /// </summary>
    /// <param name="jwk"></param>
    /// <returns></returns>
    Task AddAsync(JsonWebKey jwk);

    Task RemoveAsync(string keyId);
}
