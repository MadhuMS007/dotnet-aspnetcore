// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Globalization;
using System.Security.Claims;
using System.Text.Json;

namespace Microsoft.AspNetCore.Identity;

internal sealed class JwtReader
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
        var data = await Jwt.ReadAsync(jwtToken, algorithm, signingKey);
        return data?.Payload != null
            ? JsonSerializer.Deserialize<IDictionary<string, string>>(data.Payload)
            : null;
    }
}
