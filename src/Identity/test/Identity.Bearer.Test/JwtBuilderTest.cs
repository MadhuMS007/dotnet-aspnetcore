// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Security.Cryptography;

namespace Microsoft.AspNetCore.Identity.Test;

public class JwtBuilderTest
{
    private JsonWebKey _noneKey = new JsonWebKey(JWSAlg.None);

    [Fact]
    public async Task CanRetrieveClaims()
    {
        var payload = new Dictionary<string, string>();
        payload["email"] = "email";
        var jwtBuilder = new JwtBuilder(
            JWSAlg.None,
            "issuer",
            _noneKey,
            audience: "audience",
            subject: string.Empty,
            payload,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddMinutes(30));
        var token = await jwtBuilder.CreateJwtAsync();

        var jwtReader = new JwtReader(JWSAlg.None, "issuer", _noneKey, new string[] { "audience" });
        var user = await jwtReader.ValidateAsync(token);

        Assert.NotNull(user);
        Assert.Contains(user.Claims, c => c.Type == "email" && c.Value == "email");
    }

    [Fact]
    public async Task RejectedAfterExpires()
    {
        var jwtBuilder = new JwtBuilder(
            JWSAlg.None,
            "issuer",
            _noneKey,
            audience: "audience",
            subject: string.Empty,
            payload: null,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddMinutes(-30));
        var token = await jwtBuilder.CreateJwtAsync();

        var jwtReader = new JwtReader(JWSAlg.None, "issuer", _noneKey, new string[] { "audience" });
        Assert.Null(await jwtReader.ValidateAsync(token));
    }

    [Fact]
    public async Task RejectedBeforeNotBefore()
    {
        var jwtBuilder = new JwtBuilder(
            JWSAlg.None,
            "issuer",
            _noneKey,
            audience: "audience",
            subject: string.Empty,
            payload: null,
            DateTimeOffset.UtcNow.AddMinutes(5), // NotBefore set to 5 minutes in the future
            DateTimeOffset.UtcNow.AddMinutes(30));
        var token = await jwtBuilder.CreateJwtAsync();

        var jwtReader = new JwtReader(JWSAlg.None, "issuer", _noneKey, new string[] { "audience" });
        Assert.Null(await jwtReader.ValidateAsync(token));
    }

    [Fact]
    public async Task RejectedWrongIssuer()
    {
        var jwtBuilder = new JwtBuilder(
            JWSAlg.None,
            "badissuer",
            _noneKey,
            audience: "audience",
            subject: string.Empty,
            payload: null,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddMinutes(30));
        var token = await jwtBuilder.CreateJwtAsync();

        var jwtReader = new JwtReader(JWSAlg.None, "issuer", _noneKey, new string[] { "audience" });
        Assert.Null(await jwtReader.ValidateAsync(token));
    }

    [Fact]
    public async Task RejectedWrongAudience()
    {
        var jwtBuilder = new JwtBuilder(
            JWSAlg.None,
            "issuer",
            _noneKey,
            audience: "badaudience",
            subject: string.Empty,
            payload: null,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddMinutes(30));
        var token = await jwtBuilder.CreateJwtAsync();

        var jwtReader = new JwtReader(JWSAlg.None, "issuer", _noneKey, new string[] { "audience" });
        Assert.Null(await jwtReader.ValidateAsync(token));
    }

    /// <summary>
    /// Test.
    /// </summary>
    /// <returns>Task</returns>
    [Fact]
    public async Task CanDoHS256()
    {
        var keyBytes = new byte[32];
        RandomNumberGenerator.Fill(keyBytes);
        var base64Key = Convert.ToBase64String(keyBytes);

        // TODO: Add signing key -> key store
        var data = new Dictionary<string, string>
        {
            ["heya"] = "woo"
        };

        var jwk = new JsonWebKey("oct");
        jwk.Alg = JWSAlg.HS256;
        jwk.AdditionalData["k"] = base64Key;
        var builder = new JwtBuilder(JWSAlg.HS256, "i", jwk, "a", "s", data, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5));
        var jwt = await builder.CreateJwtAsync();

        var publicJwk = new JsonWebKey("oct");
        publicJwk.Alg = JWSAlg.HS256;
        publicJwk.AdditionalData["k"] = base64Key;

        var reader = new JwtReader(JWSAlg.HS256, "i", publicJwk, new string[] { "a" });
        var tok = await reader.ReadAsync(jwt);
        Assert.NotNull(tok);
        var payloadDict = tok.Payload as Dictionary<string, string>;
        Assert.NotNull(payloadDict);
        Assert.Equal("woo", payloadDict["heya"]);
    }

    /// <summary>
    /// Test.
    /// </summary>
    /// <returns>Task</returns>
    [Fact]
    public async Task HS256FailsWrongKey()
    {
        var keyBytes = new byte[32];
        RandomNumberGenerator.Fill(keyBytes);
        var base64Key = Convert.ToBase64String(keyBytes);

        // TODO: Add signing key -> key store
        var data = new Dictionary<string, string>
        {
            ["heya"] = "woo"
        };

        var jwk = new JsonWebKey("oct");
        jwk.Alg = JWSAlg.HS256;
        jwk.AdditionalData["k"] = base64Key;
        var builder = new JwtBuilder(JWSAlg.HS256, "i", jwk, "a", "s", data, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5));
        var jwt = await builder.CreateJwtAsync();

        var wrongJwk = new JsonWebKey("oct");
        wrongJwk.Alg = JWSAlg.HS256;
        wrongJwk.AdditionalData["k"] = "wrongkey";

        var reader = new JwtReader(JWSAlg.HS256, "i", wrongJwk, new string[] { "a" });
        var tok = await reader.ReadAsync(jwt);
        Assert.Null(tok);
    }

    /// <summary>
    /// Test.
    /// </summary>
    /// <returns>Task</returns>
    [Fact]
    public async Task CanDoRS256()
    {
        string publicKey, privateKey;
        using (var rsa = RSA.Create(2048))
        {
            privateKey = Convert.ToBase64String(rsa.ExportRSAPrivateKey());
            publicKey = Convert.ToBase64String(rsa.ExportRSAPublicKey());
        }

        var data = new Dictionary<string, string>
        {
            ["heya"] = "woo"
        };

        var privateJwk = new JsonWebKey("oct");
        privateJwk.Alg = JWSAlg.RS256;
        privateJwk.AdditionalData["k"] = privateKey;
        var builder = new JwtBuilder(JWSAlg.RS256, "i", privateJwk, "a", "s", data, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5));
        var jwt = await builder.CreateJwtAsync();

        var publicJwk = new JsonWebKey("oct");
        publicJwk.Alg = JWSAlg.RS256;
        publicJwk.AdditionalData["k"] = publicKey;

        var reader = new JwtReader(JWSAlg.RS256, "i", publicJwk, new string[] { "a" });
        var tok = await reader.ReadAsync(jwt);
        Assert.NotNull(tok);
        var payloadDict = tok.Payload as Dictionary<string, string>;
        Assert.NotNull(payloadDict);
        Assert.Equal("woo", payloadDict["heya"]);
    }

    /// <summary>
    /// Test.
    /// </summary>
    /// <returns>Task</returns>
    [Fact]
    public async Task RS256FailsWrongKey()
    {
        string publicKey, privateKey;
        using (var rsa = RSA.Create(2048))
        {
            privateKey = Convert.ToBase64String(rsa.ExportRSAPrivateKey());
            publicKey = Convert.ToBase64String(rsa.ExportRSAPublicKey());
        }

        var data = new Dictionary<string, string>
        {
            ["heya"] = "woo"
        };

        var privateJwk = new JsonWebKey("oct");
        privateJwk.Alg = JWSAlg.RS256;
        privateJwk.AdditionalData["k"] = privateKey;
        var builder = new JwtBuilder(JWSAlg.RS256, "i", privateJwk, "a", "s", data, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5));
        var jwt = await builder.CreateJwtAsync();

        var publicJwk = new JsonWebKey("oct");
        publicJwk.Alg = JWSAlg.RS256;
        using (var rsa = RSA.Create(2048))
        {
            publicJwk.AdditionalData["k"] = Convert.ToBase64String(rsa.ExportRSAPublicKey());
        }
        var reader = new JwtReader(JWSAlg.RS256, "i", publicJwk, new string[] { "a" });
        var tok = await reader.ReadAsync(jwt);
        Assert.Null(tok);
    }

}
