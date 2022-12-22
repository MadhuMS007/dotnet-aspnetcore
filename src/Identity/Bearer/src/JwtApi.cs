// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.AspNetCore.Identity;

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

// FormatOptions specifies Algorithm and the signing key so BCL can sign/validate
// jwtData contains both the header dictionary and the payload string
// CreateJwt => BclApi.CreateJwt(formatOptions, jwtData);
// ReadJwt => jwtData = BclApi.ReadJwt(formatOptions) // null or throw on failure

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

/// <summary>
/// https://www.rfc-editor.org/rfc/rfc7517
/// </summary>
public sealed class JsonWebKey
{
    /// <summary>
    /// 
    /// </summary>
    /// <param name="kty"></param>
    public JsonWebKey(string kty) => Kty = kty;

    /// <summary>
    /// 
    /// </summary>
    public IDictionary<string, string> AdditionalData { get; } = new Dictionary<string, string>();

    /// <summary>
    /// 
    /// </summary>
    public string? Alg { get; set; }

    /// <summary>
    /// 
    /// </summary>
    public string? Kid { get; set; }

    /// <summary>
    /// 
    /// </summary>
    public IList<string>? KeyOps { get; set; }

    /// <summary>
    /// 
    /// </summary>
    public string Kty { get; set; }

    /// <summary>
    /// 
    /// </summary>
    public string? Use { get; set; }

    /// <summary>
    /// 
    /// </summary>
    public string? X5c { get; set; }

    /// <summary>
    /// 
    /// </summary>
    public string? X5t { get; set; }

    /// <summary>
    /// 
    /// </summary>
    public string? X5tS256 { get; set; }

    /// <summary>
    /// 
    /// </summary>
    public string? X5u { get; set; }

    //public string Crv { get; set; }
    //public string D { get; set; }
    //public string E { get; set; }
    //public string Dp { get; set; }
    //public string Dq { get; set; }
    //public string K { get; set; }
    //public string N { get; set; }
    //public string P { get; set; }
    //public string Q { get; set; }
    //public string Qi { get; set; }
    //public string Y { get; set; }
}

internal sealed class Jwt
{

    /// <summary>
    /// The metadata, including algorithm, type
    /// </summary>
    public IDictionary<string, string> Header { get; set; } = new Dictionary<string, string>();

    /// <summary>
    /// The payload of the token.
    /// </summary>
    public string? Payload { get; set; }

    // The signature is computed from the header and payload

    //public void MakeHeader(string typ, string cty, string alg)
    //{
    //    Header["typ"] = typ;
    //    Header["cty"] = cty;
    //    Header["alg"] = alg;
    //}

    ///// <summary>
    ///// Add all the claims to the payload
    ///// </summary>
    ///// <param name="payload"></param>
    //public void MakePayload(IDictionary<string, string> payload)
    //{
    //    Payload = "payload.Serialize()";
    //}

    ///// <summary>
    ///// Turn the payload back into a dictionary
    ///// </summary>
    ///// <param name="payload"></param>
    //public IDictionary<string, string> ReadPayload()
    //{
    //    // Read payload back out into string, string
    //    return new Dictionary<string, string>();
    //}

}

internal static class BclJwt
{
    //public static string Create(string alg, Jwt data)
    //{
    //    // BCL looks up the alg, makes sure the appropriate key in header
    //    // computes the signature using the key 
    //    return "header.payload.signature";
    //}

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Trimming", "IL2026:Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code", Justification = "<Pending>")]
    public static string CreateJwt(Jwt jwt, string algorithm, JsonWebKey? key)
    {
        jwt.Header["alg"] = algorithm;
        jwt.Header["typ"] = "JWT";
        if (algorithm == JWSAlg.None)
        {
            // Just send the payload as the jwt
            return jwt.Payload ?? string.Empty;
        }
        else // TEMPORARY: Just encode the header and payload and key as the format
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            return $"{Base64UrlEncoder.Encode(JsonSerializer.Serialize(jwt.Header))}.{Base64UrlEncoder.Encode(jwt.Payload)}.{key.Kid}";
        }
        throw new InvalidOperationException($"Unsupported alg: {algorithm}.");
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Trimming", "IL2026:Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code", Justification = "<Pending>")]
    public static Jwt? ReadJwt(string jwt, string algorithm, JsonWebKey? key)
    {
        var data = new Jwt();
        if (algorithm == JWSAlg.None)
        {
            data.Payload = jwt;
            return data;
        }
        else
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            var sections = jwt.Split('.');
            if (sections.Length != 3)
            {
                return null; // Expected 3 sections
            }
            var header = JsonSerializer.Deserialize<IDictionary<string, string>>(Base64UrlEncoder.Decode(sections[0]));
            if (header?["alg"] != algorithm || sections[2] != key.Kid)
            {
                return null; // Expected 3 sections and key to be the last section
            }
            data.Header = header;
            data.Payload = Base64UrlEncoder.Decode(sections[1]);
            return data;

        }
        throw new InvalidOperationException($"Unsupported alg: {algorithm}.");
    }
}

/// <summary>
/// 
/// </summary>
public class JwtBuilder
{
    /// <summary>
    /// 
    /// </summary>
    /// <param name="algorithm"></param>
    /// <param name="issuer"></param>
    /// <param name="signingKey"></param>
    /// <param name="audience"></param>
    /// <param name="payload"></param>
    /// <param name="notBefore"></param>
    /// <param name="expires"></param>
    public JwtBuilder(string algorithm, string issuer, JsonWebKey signingKey, string audience, IDictionary<string, string> payload, DateTimeOffset notBefore, DateTimeOffset expires)
    {
        Algorithm = algorithm;
        Issuer = issuer;
        SigningKey = signingKey;
        Audience = audience;
        Payload = payload;
        NotBefore = notBefore;
        Expires = expires;
    }

    /// <summary>
    /// The Algorithm for the JWT.
    /// </summary>
    public string Algorithm { get; set; }

    /// <summary>
    /// The Issuer for the token
    /// </summary>
    public string Issuer { get; set; }

    /// <summary>
    /// The signing key to use
    /// </summary>
    public JsonWebKey SigningKey { get; set; }

    /// <summary>
    /// 
    /// </summary>
    public string Audience { get; set; }

    /// <summary>
    /// 
    /// </summary>
    public IDictionary<string, string> Payload{ get; set; }

    /// <summary>
    /// 
    /// </summary>
    public DateTimeOffset NotBefore { get; set; }

    /// <summary>
    /// 
    /// </summary>
    public DateTimeOffset Expires { get; set; }

    /// <summary>
    /// 
    /// </summary>
    /// <returns></returns>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Trimming", "IL2026:Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code", Justification = "<Pending>")]
    public string CreateJwt()
    {
        var jwtData = new Jwt();
        jwtData.Payload = JsonSerializer.Serialize(Payload);

        return BclJwt.CreateJwt(jwtData, Algorithm, SigningKey);

        //var handler = new JwtSecurityTokenHandler();

        //var jwtToken = handler.CreateJwtSecurityToken(
        //    Issuer,
        //    Audience,
        //    Identity,
        //    NotBefore.UtcDateTime,
        //    Expires.UtcDateTime,
        //    //REVIEW: Do we want this configurable?
        //    issuedAt: DateTime.UtcNow,
        //    SigningCredentials);

        //return handler.WriteToken(jwtToken);
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="jwtToken"></param>
    /// <param name="algorithm"></param>
    /// <param name="signingKey"></param>
    /// <returns></returns>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Trimming", "IL2026:Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code", Justification = "<Pending>")]
    public static IDictionary<string, string>? ReadJwt(string jwtToken, string algorithm, JsonWebKey? signingKey)
    {
        var data = BclJwt.ReadJwt(jwtToken, algorithm, signingKey);
        return data?.Payload != null
            ? JsonSerializer.Deserialize<IDictionary<string, string>>(data.Payload)
            : null;
    }
}
