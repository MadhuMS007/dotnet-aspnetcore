// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

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

}
