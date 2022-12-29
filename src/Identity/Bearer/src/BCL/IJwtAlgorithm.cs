// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Microsoft.IdentityModel.Tokens;
using System.Text.Json;

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

/// <summary>
/// Constants for 'alg' https://www.rfc-editor.org/rfc/rfc7518#section-3.1
/// </summary>
public static class JWSAlg
{
    /// <summary>
    /// HS256
    /// </summary>
    public static readonly string HS256 = "HS256";

    ///// <summary>
    ///// HS384
    ///// </summary>
    //public static readonly string HS384 = "HS384";

    ///// <summary>
    ///// HS512
    ///// </summary>
    //public static readonly string HS512 = "HS512";

    ///// <summary>
    ///// RS256
    ///// </summary>
    //public static readonly string RS256 = "RS256";

    ///// <summary>
    ///// RS384
    ///// </summary>
    //public static readonly string RS384 = "RS384";

    ///// <summary>
    ///// RS512
    ///// </summary>
    //public static readonly string RS512 = "RS512";

    ///// <summary>
    ///// ES256
    ///// </summary>
    //public static readonly string ES256 = "ES256";

    ///// <summary>
    ///// ES384
    ///// </summary>
    //public static readonly string ES384 = "ES384";

    ///// <summary>
    ///// ES512
    ///// </summary>
    //public static readonly string ES512 = "ES512";

    ///// <summary>
    ///// PS256
    ///// </summary>
    //public static readonly string PS256 = "PS256";

    ///// <summary>
    ///// PS384
    ///// </summary>
    //public static readonly string PS384 = "PS384";

    ///// <summary>
    ///// PS512
    ///// </summary>
    //public static readonly string PS512 = "PS512";

    /// <summary>
    /// none
    /// </summary>
    public static readonly string None = "none";
}

internal sealed class JwtAlgNone : IJwtAlgorithm
{
    public Task<string> CreateJwtAsync(Jwt jwt, JsonWebKey? key)
        // Just send the payload as the jwt
        => Task.FromResult(jwt.Payload ?? string.Empty);

    public Task<Jwt?> ReadJwtAsync(string jwtToken, JsonWebKey? key)
    {
        var data = new Jwt(JWSAlg.None);
        data.Header.Type = "JWT";
        data.Payload = jwtToken;
        return Task.FromResult<Jwt?>(data);
    }

    public Task<bool> ValidateKeyAsync(JsonWebKey? key)
        => Task.FromResult(true);
}

internal sealed class JwtAlgHS256 : IJwtAlgorithm
{
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Trimming", "IL2026:Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code", Justification = "<Pending>")]
    public Task<string> CreateJwtAsync(Jwt jwt, JsonWebKey? key)
    {
        jwt.Header = new JwtHeader(JWSAlg.HS256);
        jwt.Header.Type = "JWT";
        // TODO: This should actually do HS256 using the key to sign, instead of just sending the key as the signature
        return Task.FromResult($"{Base64UrlEncoder.Encode(JsonSerializer.Serialize(jwt.Header))}.{Base64UrlEncoder.Encode(jwt.Payload)}.{key!.Kid}");
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Trimming", "IL2026:Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code", Justification = "<Pending>")]
    public Task<Jwt?> ReadJwtAsync(string jwtToken, JsonWebKey? key)
    {
        if (key == null)
        {
            return Task.FromResult<Jwt?>(null);
        }

        var sections = jwtToken.Split('.');
        if (sections.Length != 3)
        {
            // Expected 3 sections
            return Task.FromResult<Jwt?>(null);
        }
        var header = JsonSerializer.Deserialize<IDictionary<string, string>>(Base64UrlEncoder.Decode(sections[0]));
        // TODO: Actually do HS256 signing
        if (header?["alg"] != "HS256" || header?["typ"] != "JWT" || sections[2] != key.Kid)
        {
            // Expected HS256 alg and key to be the last section
            return Task.FromResult<Jwt?>(null);
        }
        var data = new Jwt(new JwtHeader(header));
        data.Payload = Base64UrlEncoder.Decode(sections[1]);
        return Task.FromResult<Jwt?>(data);
    }

    public Task<bool> ValidateKeyAsync(JsonWebKey? key)
        => Task.FromResult(key != null && key.Kid != null);
}
