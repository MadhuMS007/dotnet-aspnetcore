// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace Microsoft.AspNetCore.Identity;

internal interface IJwtAlgorithm
{
    /// <summary>
    /// Ensures the necessary data for this Jwt Algorithm is contained in the key (if provided).
    /// </summary>
    /// <param name="key"></param>
    /// <returns></returns>
    public abstract Task<bool> ValidateKeyAsync(JsonWebKey? key);

    /// <summary>
    /// Create a Jwt using the specified key for this algorithm.
    /// </summary>
    /// <param name="jwt"></param>
    /// <param name="key"></param>
    /// <returns></returns>
    public abstract Task<string> CreateJwtAsync(Jwt jwt, JsonWebKey? key);

    /// <summary>
    /// Attempts to decode the jwtToken using the specified key for this algorithm.
    /// </summary>
    /// <param name="jwtToken">The jwtToken string.</param>
    /// <param name="key">The JWK used for signing.</param>
    /// <returns>The JWT data.</returns>
    public abstract Task<Jwt?> ReadJwtAsync(string jwtToken, JsonWebKey? key);
}
