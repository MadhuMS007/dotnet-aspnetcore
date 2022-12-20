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

internal sealed class JwtData
{

    /// <summary>
    /// The metadata, including algorithm, type
    /// </summary>
    public IDictionary<string, string> Header { get; } = new Dictionary<string, string>();

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
    //public static string Create(string alg, JwtData data)
    //{
    //    // BCL looks up the alg, makes sure the appropriate key in header
    //    // computes the signature using the key 
    //    return "header.payload.signature";
    //}

    public static string CreateJwt(JwtData jwt)
    {
        // Just send the payload as the jwt
        return jwt.Payload ?? string.Empty;
    }

    public static JwtData ReadJwt(string jwt)
    {
        var data = new JwtData();
        data.Payload = jwt;
        return data;
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
    /// <param name="issuer"></param>
    /// <param name="signingCredentials"></param>
    /// <param name="audience"></param>
    /// <param name="payload"></param>
    /// <param name="notBefore"></param>
    /// <param name="expires"></param>
    public JwtBuilder(string issuer, SigningCredentials signingCredentials, string audience, IDictionary<string, string> payload, DateTimeOffset notBefore, DateTimeOffset expires)
    {
        Issuer = issuer;
        SigningCredentials = signingCredentials;
        Audience = audience;
        Payload = payload;
        NotBefore = notBefore;
        Expires = expires;
    }

    /// <summary>
    /// The Issuer for the token
    /// </summary>
    public string Issuer { get; set; }

    /// <summary>
    /// The <see cref="SigningCredentials"/> to use.
    /// </summary>
    public SigningCredentials SigningCredentials { get; set; }

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
        var jwtData = new JwtData();
        jwtData.Payload = JsonSerializer.Serialize(Payload);
        jwtData.Header["alg"] = JWSAlg.None;

        return BclJwt.CreateJwt(jwtData);

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
    /// <returns></returns>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Trimming", "IL2026:Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code", Justification = "<Pending>")]
    public static IDictionary<string, string>? ReadJwt(string jwtToken)
    {
        var data = BclJwt.ReadJwt(jwtToken);
        return data?.Payload != null
            ? JsonSerializer.Deserialize<IDictionary<string, string>>(data.Payload)
            : null;
    }
}
