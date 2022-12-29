// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Security.Claims;
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

internal sealed class JwtHeader : IDictionary<string, string>
{
    public string this[string key] { get => Headers[key]; set => Headers[key] = value; }

    /// <summary>
    /// Constructor, alg is required.
    /// </summary>
    /// <param name="alg"></param>
    public JwtHeader(string alg) => Alg = alg;

    public JwtHeader(IDictionary<string, string> headers)
    {
        if (!headers.ContainsKey("alg"))
        {
            throw new ArgumentException("alg must be specified.", nameof(headers));
        }
        Headers = headers;
    }

    /// <summary>
    /// The actual headers.
    /// </summary>
    public IDictionary<string, string> Headers { get; } = new Dictionary<string, string>();

    /// <summary>
    /// Maps to the Headers["alg"] representing the Algorithm for the JWT.
    /// </summary>
    public string Alg
    {
        get => Headers["alg"];
        private set => Headers["alg"] = value;
    }

    /// <summary>
    /// Maps to the Headers["typ"] representing the Type of the JWT.
    /// </summary>
    public string Type
    {
        get => Headers["typ"];
        set => Headers["typ"] = value;
    }

    public string ContentType
    {
        get => Headers["cty"];
        set => Headers["cty"] = value;
    }

    public ICollection<string> Keys => Headers.Keys;

    public ICollection<string> Values => Headers.Values;

    public int Count => Headers.Count;

    public bool IsReadOnly => Headers.IsReadOnly;

    public void Add(string key, string value)
        => Headers.Add(key, value);

    public void Add(KeyValuePair<string, string> item)
        => Headers.Add(item);

    public void Clear()
        => Headers.Clear();

    public bool Contains(KeyValuePair<string, string> item)
        => Headers.Contains(item);

    public bool ContainsKey(string key)
        => Headers.ContainsKey(key);

    public void CopyTo(KeyValuePair<string, string>[] array, int arrayIndex)
        => Headers.CopyTo(array, arrayIndex);

    public IEnumerator<KeyValuePair<string, string>> GetEnumerator()
        => Headers.GetEnumerator();

    public bool Remove(string key)
        => Headers.Remove(key);

    public bool Remove(KeyValuePair<string, string> item)
        => Headers.Remove(item);

    public bool TryGetValue(string key, [MaybeNullWhen(false)] out string value)
        => Headers.TryGetValue(key, out value); 

    IEnumerator IEnumerable.GetEnumerator()
        => ((IEnumerable)Headers).GetEnumerator();
}

internal sealed class Jwt
{
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
}

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

internal static class BclJwt
{
    public static IDictionary<string, IJwtAlgorithm> Algorithms { get; } = new Dictionary<string, IJwtAlgorithm>();

    static BclJwt()
    {
        Algorithms[JWSAlg.None] = new JwtAlgNone();
        Algorithms[JWSAlg.HS256] = new JwtAlgHS256();
    }

    public static Task<string> CreateJwtAsync(Jwt jwt, string algorithm, JsonWebKey? key)
    {
        if (!Algorithms.ContainsKey(algorithm))
        {
            throw new InvalidOperationException($"Unknown algorithm: {algorithm}.");
        }

        return Algorithms[algorithm].CreateJwtAsync(jwt, key);
    }

    public static Task<Jwt?> ReadJwtAsync(string jwt, string algorithm, JsonWebKey? key)
    {
        if (!Algorithms.ContainsKey(algorithm))
        {
            throw new InvalidOperationException($"Unknown algorithm: {algorithm}.");
        }

        return Algorithms[algorithm].ReadJwtAsync(jwt, key);
    }
}

internal class JwtReader
{
    /// <summary>
    /// 
    /// </summary>
    /// <param name="algorithm"></param>
    /// <param name="issuer"></param>
    /// <param name="signingKey"></param>
    /// <param name="audience"></param>
    public JwtReader(string algorithm, string issuer, JsonWebKey signingKey, string audience)
    {
        Algorithm = algorithm;
        Issuer = issuer;
        SigningKey = signingKey;
        Audience = audience;
    }

    /// <summary>
    /// The Algorithm for the JWT.
    /// </summary>
    public string Algorithm { get; set; }

    /// <summary>
    /// The Issuer for the JWT.
    /// </summary>
    public string Issuer { get; set; }

    /// <summary>
    /// The signing key to use.
    /// </summary>
    public JsonWebKey SigningKey { get; set; }

    /// <summary>
    /// The intended audience for the JWT.
    /// </summary>
    public string Audience { get; set; }

    private static string? SafeGet(IDictionary<string, string> payload, string key)
    {
        payload.TryGetValue(key, out var value);
        return value;
    }

    private static bool SafeBeforeDateCheck(IDictionary<string, string> payload, string key)
    {
        var date = SafeGet(payload, key);
        if (date == null)
        {
            return false;
        }
        if (DateTimeOffset.UtcNow > FromUtcTicks(date))
        {
            return false;
        }
        return true;
    }

    private static bool SafeAfterDateCheck(IDictionary<string, string> payload, string key)
    {
        var date = SafeGet(payload, key);
        if (date == null)
        {
            return false;
        }
        if (DateTimeOffset.UtcNow < FromUtcTicks(date))
        {
            return false;
        }
        return true;
    }

    private static DateTimeOffset FromUtcTicks(string utcTicks)
        => new DateTimeOffset(long.Parse(utcTicks, CultureInfo.InvariantCulture), TimeSpan.Zero);

    // Make sure that the payload is valid and not expired
    private bool ValidatePayload(IDictionary<string, string> payload)
    {
        var issuer = SafeGet(payload, "iss");
        if (issuer != Issuer)
        {
            return false;
        }

        // REVIEW: more than one valid?
        var audience = SafeGet(payload, "aud");
        if (audience != Audience)
        {
            return false;
        }

        // Make sure JWT is not expired
        if (!SafeBeforeDateCheck(payload, "exp"))
        {
            return false;
        }

        // Make sure JWT is not too early
        if (!SafeAfterDateCheck(payload, "nbf"))
        {
            return false;
        }

        // REVIEW: should we ensure iat is present?
        // REVIEW: should we set subject or check that it matches?

        return true;
    }

    /// <summary>
    /// Attempts to validate a JWT, returns the payload as a ClaimsPrincipal if successful.
    /// </summary>
    /// <param name="jwtToken">The JWT.</param>
    /// <returns>A ClaimsPrincipal if the JWT is valid.</returns>
    public async Task<ClaimsPrincipal?> ValidateJwtAsync(string jwtToken)
    {
        var payload = await ReadJwtAsync(jwtToken, Algorithm, SigningKey);
        if (payload != null)
        {
            // Ensure that the payload is valid.
            if (!ValidatePayload(payload))
            {
                return null;
            }

            // REVIEW: should we take the scheme name?
            var claimsIdentity = new ClaimsIdentity(IdentityConstants.BearerScheme);
            foreach (var key in payload.Keys)
            {
                claimsIdentity.AddClaim(new Claim(key, payload[key]));
            }
            return new ClaimsPrincipal(claimsIdentity);
        }
        return null;

    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="jwtToken"></param>
    /// <param name="algorithm"></param>
    /// <param name="signingKey"></param>
    /// <returns></returns>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Trimming", "IL2026:Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code", Justification = "<Pending>")]
    public static async Task<IDictionary<string, string>?> ReadJwtAsync(string jwtToken, string algorithm, JsonWebKey? signingKey)
    {
        var data = await BclJwt.ReadJwtAsync(jwtToken, algorithm, signingKey);
        return data?.Payload != null
            ? JsonSerializer.Deserialize<IDictionary<string, string>>(data.Payload)
            : null;
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
    /// <param name="subject"></param>
    /// <param name="payload"></param>
    /// <param name="notBefore"></param>
    /// <param name="expires"></param>
    public JwtBuilder(string algorithm, string issuer, JsonWebKey signingKey, string audience, string subject, IDictionary<string, string>? payload, DateTimeOffset notBefore, DateTimeOffset expires)
    {
        Algorithm = algorithm;
        Issuer = issuer;
        SigningKey = signingKey;
        Audience = audience;
        Subject = subject;
        Payload = payload ?? new Dictionary<string, string>();
        NotBefore = notBefore;
        Expires = expires;
    }

    /// <summary>
    /// The Algorithm for the JWT.
    /// </summary>
    public string Algorithm { get; set; }

    /// <summary>
    /// The Issuer for the JWT.
    /// </summary>
    public string Issuer { get; set; }

    /// <summary>
    /// The signing key to use.
    /// </summary>
    public JsonWebKey SigningKey { get; set; }

    /// <summary>
    /// The intended audience for the JWT.
    /// </summary>
    public string Audience { get; set; }

    /// <summary>
    /// The claims payload for the JWT.
    /// </summary>
    public IDictionary<string, string> Payload { get; set; }

    /// <summary>
    /// Specifies when the JWT must not be accepted before.
    /// </summary>
    public DateTimeOffset NotBefore { get; set; }

    /// <summary>
    /// Specifies when the JWT expires.
    /// </summary>
    public DateTimeOffset Expires { get; set; }

    /// <summary>
    /// The time this JWT was issued, if null, DateTimeOffset.Now will be used.
    /// </summary>
    public DateTimeOffset? IssuedAt { get; set; }

    /// <summary>
    /// The subject(user) of the JWT.
    /// </summary>
    public string Subject { get; set; }

    /// <summary>
    /// The JWT ID, a unique identifier which can be used to prevent replay.
    /// </summary>
    public string? Jti { get; set; }

    private void SetReservedPayload(string key, string value)
    {
        if (Payload.ContainsKey(key))
        {
            throw new InvalidOperationException($"The key: {key} is reserved and must not be set in Payload.");
        }
        Payload[key] = value;
    }

    // Add the validation settings to the payload and make sure the reserved keys aren't set.
    private void PreparePayload()
    {
        SetReservedPayload("iss", Issuer);
        SetReservedPayload("aud", Audience);
        SetReservedPayload("sub", Subject);

        var issuedAt = IssuedAt ?? DateTimeOffset.UtcNow;
        SetReservedPayload("iat", issuedAt.UtcTicks.ToString(CultureInfo.InvariantCulture));
        SetReservedPayload("exp", Expires.UtcTicks.ToString(CultureInfo.InvariantCulture));
        SetReservedPayload("nbf", NotBefore.UtcTicks.ToString(CultureInfo.InvariantCulture));
        if (Jti != null)
        {
            SetReservedPayload("jti", Jti);
        }
    }

    /// <summary>
    /// 
    /// </summary>
    /// <returns></returns>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Trimming", "IL2026:Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code", Justification = "<Pending>")]
    public Task<string> CreateJwtAsync()
    {
        // Generate JTI if null
        if (Jti == null)
        {
            Jti = Guid.NewGuid().ToString();
        }

        // TODO: add the metadata claims
        PreparePayload();

        var jwtData = new Jwt(Algorithm)
        {
            Payload = JsonSerializer.Serialize(Payload)
        };

        return BclJwt.CreateJwtAsync(jwtData, Algorithm, SigningKey);

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
    public static async Task<IDictionary<string, string>?> ReadJwtAsync(string jwtToken, string algorithm, JsonWebKey? signingKey)
    {
        var data = await BclJwt.ReadJwtAsync(jwtToken, algorithm, signingKey);
        return data?.Payload != null
            ? JsonSerializer.Deserialize<IDictionary<string, string>>(data.Payload)
            : null;
    }
}
