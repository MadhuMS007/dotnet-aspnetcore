// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace Microsoft.AspNetCore.Identity;

internal sealed class Jwt
{
    public static IDictionary<string, IJwtAlgorithm> Algorithms { get; } = new Dictionary<string, IJwtAlgorithm>();

    static Jwt()
    {
        Algorithms[JWSAlg.None] = new JwtAlgNone();
        Algorithms[JWSAlg.HS256] = new JwtAlgHS256();
    }

    /// <summary>
    /// Creates a new Jwt with the specified algorithm
    /// </summary>
    /// <param name="alg">The algorithm for the JWT.</param>
    public Jwt(string alg)
        => Header = new JwtHeader(alg);

    /// <summary>
    /// Creates a new Jwt with the specified header
    /// </summary>
    /// <param name="header">the JWT header.</param>
    public Jwt(JwtHeader header)
        => Header = header;

    /// <summary>
    /// The metadata, including algorithm, type
    /// </summary>
    public JwtHeader Header { get; set; }

    /// <summary>
    /// The payload of the token.
    /// </summary>
    public string? Payload { get; set; }

    // The signature is computed from the header and payload


    public static Task<string> CreateAsync(Jwt jwt, string algorithm, JsonWebKey? key)
    {
        if (!Algorithms.ContainsKey(algorithm))
        {
            throw new InvalidOperationException($"Unknown algorithm: {algorithm}.");
        }

        return Algorithms[algorithm].CreateJwtAsync(jwt, key);
    }

    public static Task<Jwt?> ReadAsync(string jwt, string algorithm, JsonWebKey? key)
    {
        if (!Algorithms.ContainsKey(algorithm))
        {
            throw new InvalidOperationException($"Unknown algorithm: {algorithm}.");
        }

        return Algorithms[algorithm].ReadJwtAsync(jwt, key);
    }
}
