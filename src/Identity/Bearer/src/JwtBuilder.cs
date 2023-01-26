// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Globalization;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;

namespace Microsoft.AspNetCore.Identity;

/// <summary>
/// 
/// </summary>
public class JwtBuilder : TokenBuilder
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
    public JwtBuilder(string algorithm, string issuer, JsonWebKey? signingKey, string audience, string subject, IDictionary<string, string> payload, DateTimeOffset notBefore, DateTimeOffset expires)
        : base(subject, expires, payload)
    {
        Algorithm = algorithm;
        Issuer = issuer;
        SigningKey = signingKey;
        Audience = audience;
        NotBefore = notBefore;
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
    public JsonWebKey? SigningKey { get; set; }

    /// <summary>
    /// The intended audience for the JWT.
    /// </summary>
    public string Audience { get; set; }

    /// <summary>
    /// Specifies when the JWT must not be accepted before.
    /// </summary>
    public DateTimeOffset NotBefore { get; set; }

    /// <summary>
    /// The time this JWT was issued, if null, DateTimeOffset.Now will be used.
    /// </summary>
    public DateTimeOffset? IssuedAt { get; set; }

    /// <summary>
    /// The JWT ID, a unique identifier which can be used to prevent replay.
    /// </summary>
    public string? Jti { get; set; }

    /// <summary>
    /// If set, the jwt payload will be additional protected with dataprotection
    /// </summary>
    public IDataProtector? PayloadProtector { get; set; }

    private void SetReservedPayload(string key, string value)
    {
        if (RawToken.ContainsKey(key))
        {
            throw new InvalidOperationException($"The key: {key} is reserved and must not be set in Payload.");
        }
        RawToken[key] = value;
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
            Jti = Guid.NewGuid().ToString().GetHashCode().ToString("x", CultureInfo.InvariantCulture);
        }

        // TODO: add the metadata claims
        PreparePayload();

        var jwtData = new Jwt(Algorithm)
        {
            Payload = JsonSerializer.Serialize(RawToken)
        };
        if (PayloadProtector != null)
        {
            jwtData.Payload = PayloadProtector.Protect(jwtData.Payload);
        }

        return Jwt.CreateAsync(jwtData, Algorithm, SigningKey);
    }
}
