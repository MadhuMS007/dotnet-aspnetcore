// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Globalization;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;

namespace Microsoft.AspNetCore.Identity;

// TODO: Add required claims validation, exact match, required, and forbidden lists
internal sealed class JwtReader
{
    /// <summary>
    /// 
    /// </summary>
    /// <param name="algorithm"></param>
    /// <param name="validIssuer"></param>
    /// <param name="signingKey"></param>
    /// <param name="validAudiences"></param>
    public JwtReader(string algorithm, string? validIssuer = null, JsonWebKey? signingKey = null, IList<string>? validAudiences = null)
    {
        Algorithm = algorithm;
        ValidIssuer = validIssuer;
        SigningKey = signingKey;
        ValidAudiences = validAudiences;
    }

    /// <summary>
    /// The Algorithm for the JWT.
    /// </summary>
    public string Algorithm { get; set; }

    /// <summary>
    /// The Issuer for the JWT.
    /// </summary>
    public string? ValidIssuer { get; set; }

    /// <summary>
    /// The signing key to use.
    /// </summary>
    public JsonWebKey? SigningKey { get; set; }

    /// <summary>
    /// The intended audiences for the JWT.
    /// </summary>
    public IList<string>? ValidAudiences { get; set; }

    /// <summary>
    /// IF set, the payload will be additional unprotected with dataprotection
    /// </summary>
    public IDataProtector? PayloadProtector { get; set; }

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

    private bool ValidateIssuer(IDictionary<string, string> payload)
        => ValidIssuer == null || SafeGet(payload, "iss") == ValidIssuer;

    // Make sure that the payload is valid and not expired
    private bool ValidatePayload(IDictionary<string, string> payload)
    {
        if (!ValidateIssuer(payload))
        {
            return false;
        }

        // REVIEW: more than one valid?
        var audience = SafeGet(payload, "aud");
        if (ValidAudiences != null &&
            (audience == null || !ValidAudiences.Contains(audience)))
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
    public async Task<ClaimsPrincipal?> ValidateAsync(string jwtToken)
    {
        var payload = await ReadPayloadAsync(jwtToken);
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

    private static TokenInfo? FromTokenInfo(IDictionary<string, string> payload)
    {
        var sub = SafeGet(payload, TokenClaims.Subject);
        if (sub == null)
        {
            return null;
        }

        var jti = SafeGet(payload, TokenClaims.Jti);
        if (jti == null)
        {
            return null;
        }
        return new TokenInfo(jti, TokenFormat.JWT, sub, TokenPurpose.AccessToken, TokenStatus.Active)
        {
            Payload = payload
        };
    }

    public async Task<TokenInfo?> ReadAsync(string jwtToken)
    {
        var payload = await ReadPayloadAsync(jwtToken);
        if (payload != null)
        {
            // Ensure that the payload is valid.
            if (!ValidatePayload(payload))
            {
                return null;
            }

            return FromTokenInfo(payload);
        }
        return null;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="jwtToken"></param>
    /// <returns></returns>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Trimming", "IL2026:Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code", Justification = "<Pending>")]
    private async Task<IDictionary<string, string>?> ReadPayloadAsync(string jwtToken)
    {
        var data = await Jwt.ReadAsync(jwtToken, Algorithm, SigningKey);
        if (data?.Payload == null)
        {
            return null;
        }
        if (PayloadProtector != null)
        {
            data.Payload = PayloadProtector.Unprotect(data.Payload);
        }
        return JsonSerializer.Deserialize<IDictionary<string, string>>(data.Payload);
    }
}
