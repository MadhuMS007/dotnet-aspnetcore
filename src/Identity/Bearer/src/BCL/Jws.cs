// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;

namespace Microsoft.AspNetCore.Identity;

/// <summary>
/// Constants for 'alg' https://www.rfc-editor.org/rfc/rfc7518#section-3.1
/// </summary>
public static class JWSAlg
{
    /// <summary>
    /// HS256
    /// </summary>
    public const string HS256 = "HS256";

    ///// <summary>
    ///// HS384
    ///// </summary>
    //public static readonly string HS384 = "HS384";

    ///// <summary>
    ///// HS512
    ///// </summary>
    //public static readonly string HS512 = "HS512";

    /// <summary>
    /// RS256
    /// </summary>
    public const string RS256 = "RS256";

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
    public const string None = "none";
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

internal abstract class JwsAlg : IJwtAlgorithm
{
    public abstract string HeaderAlg { get; }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Trimming", "IL2026:Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code", Justification = "<Pending>")]
    public virtual Task<string> CreateJwtAsync(Jwt jwt, JsonWebKey? key)
    {
        jwt.Header = new JwtHeader(HeaderAlg);
        jwt.Header.Type = "JWT";

        var headerJson = JsonSerializer.Serialize(jwt.Header);

        var encodedHeaderPayload = $"{WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(jwt.Header)))}.{WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(jwt.Payload))}";
        var signature = ComputeSignature(encodedHeaderPayload, key);
        return Task.FromResult($"{WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson))}.{WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(jwt.Payload))}.{signature}");
    }

    protected abstract string ComputeSignature(string encodedHeaderPayload, JsonWebKey? key);

    protected virtual bool ValidateSignature(string signature, string encodedHeaderPayload, JsonWebKey? key)
        => signature == ComputeSignature(encodedHeaderPayload, key);

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Trimming", "IL2026:Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code", Justification = "<Pending>")]
    public virtual Task<Jwt?> ReadJwtAsync(string jwtToken, JsonWebKey? key)
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
        var header = JsonSerializer.Deserialize<IDictionary<string, string>>(WebEncoders.Base64UrlDecode(sections[0]));
        if (header?["alg"] != HeaderAlg || header?["typ"] != "JWT" || !ValidateSignature(sections[2], $"{sections[0]}.{sections[1]}", key))
        {
            // Signature failed.
            return Task.FromResult<Jwt?>(null);
        }
        var data = new Jwt(new JwtHeader(header!));
        data.Payload = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(sections[1]));
        return Task.FromResult<Jwt?>(data);
    }

    public virtual Task<bool> ValidateKeyAsync(JsonWebKey? key)
        => Task.FromResult(key != null && key.AdditionalData["k"] != null);
}

internal sealed class JwtAlgHS256 : JwsAlg
{
    public override string HeaderAlg => JWSAlg.HS256;

    protected override string ComputeSignature(string encodedHeaderPayload, JsonWebKey? key)
    {
        var keyBytes = WebEncoders.Base64UrlDecode(key!.AdditionalData["k"]);
        using (var hmac = new HMACSHA256(keyBytes))
        {
            return WebEncoders.Base64UrlEncode(hmac.ComputeHash(Encoding.Unicode.GetBytes(encodedHeaderPayload)));
        }
    }
}

internal sealed class JwtAlgRS256 : JwsAlg
{
    public override string HeaderAlg => JWSAlg.RS256;

    protected override string ComputeSignature(string encodedHeaderPayload, JsonWebKey? key)
    {
        using (var rsa = RSA.Create(2048))
        {
            rsa.ImportRSAPrivateKey(WebEncoders.Base64UrlDecode(key!.AdditionalData["k"]), out var bytesRead);
            return WebEncoders.Base64UrlEncode(rsa.SignData(Encoding.Unicode.GetBytes(encodedHeaderPayload), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        }
    }

    protected override bool ValidateSignature(string signature, string encodedHeaderPayload, JsonWebKey? key)
    {
        // Verify the signature
        using (var rsa = RSA.Create(2048))
        {
            rsa.ImportRSAPublicKey(WebEncoders.Base64UrlDecode(key!.AdditionalData["k"]), out var bytesRead);
            var headerBytes = Encoding.Unicode.GetBytes(encodedHeaderPayload);
            return rsa.VerifyData(headerBytes,
                    WebEncoders.Base64UrlDecode(signature),
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);
        }
    }
}
