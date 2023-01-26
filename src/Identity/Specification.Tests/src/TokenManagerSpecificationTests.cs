// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Linq;
using System.Linq.Expressions;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Xunit;

namespace Microsoft.AspNetCore.Identity.Test;

public abstract class TokenManagerSpecificationTestBase<TUser> : TokenManagerSpecificationTestBase<TUser, string> where TUser : class { }

/// <summary>
/// Base class for tests that exercise basic identity functionality that all stores should support.
/// </summary>
/// <typeparam name="TUser">The type of the user.</typeparam>
/// <typeparam name="TKey">The primary key type.</typeparam>
public abstract class TokenManagerSpecificationTestBase<TUser, TKey>
    where TUser : class
    where TKey : IEquatable<TKey>
{
    /// <summary>
    /// Null value.
    /// </summary>
    protected const string NullValue = "(null)";

    /// <summary>
    /// Error describer.
    /// </summary>
    protected readonly IdentityErrorDescriber _errorDescriber = new IdentityErrorDescriber();

    /// <summary>
    /// Configure the service collection used for tests.
    /// </summary>
    /// <param name="services"></param>
    /// <param name="context"></param>
    protected virtual void SetupIdentityServices(IServiceCollection services, object context)
        => SetupBuilder(services, context);

    /// <summary>
    /// Configure the service collection used for tests.
    /// </summary>
    /// <param name="services"></param>
    /// <param name="context"></param>
    protected virtual IdentityBuilder SetupBuilder(IServiceCollection services, object context)
    {
        services.AddHttpContextAccessor();
        // An example of what the expected schema looks like
        // "Authentication": {
        //     "Schemes": {
        //       "Identity.Bearer": {
        //         "Audiences": [ "", ""]
        //         "Issuer": "",
        // An example of what the expected signing keys (JWKs) looks like
        //"SigningCredentials": {
        //  "kty": "oct",
        //  "alg": "HS256",
        //  "kid": "randomguid",
        //  "k": "(G+KbPeShVmYq3t6w9z$C&F)J@McQfTj"
        //}
        //       }
        //     }
        //   }

        services.AddSingleton<IConfiguration>(new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string>
            {
                ["Authentication:Schemes:Identity.Bearer:SigningCredentials:kty"] = "oct",
                ["Authentication:Schemes:Identity.Bearer:SigningCredentials:alg"] = "HS256",
                ["Authentication:Schemes:Identity.Bearer:SigningCredentials:kid"] = "someguid",
            })
            .Build());

        // We need to configure a default signing key
        var keyBytes = new byte[32];
        RandomNumberGenerator.Fill(keyBytes);
        var base64Key = Convert.ToBase64String(keyBytes);

        services.AddAuthentication();
        services.AddDataProtection();
        services.AddSingleton<IDataProtectionProvider, EphemeralDataProtectionProvider>();
        var builder = services.AddDefaultIdentityBearer<TUser, IdentityStoreToken>(options =>
        {
            options.Password.RequireDigit = false;
            options.Password.RequireLowercase = false;
            options.Password.RequireNonAlphanumeric = false;
            options.Password.RequireUppercase = false;
            options.User.AllowedUserNameCharacters = null;
        }).AddDefaultTokenProviders();
        AddUserStore(services, context);
        AddTokenStore(services, context);
        services.AddLogging();
        services.AddSingleton<ILogger<UserManager<TUser>>>(new TestLogger<UserManager<TUser>>());
        return builder;
    }

    protected abstract void AddUserStore(IServiceCollection services, object context = null);

    protected abstract void AddTokenStore(IServiceCollection services, object context = null);

    protected abstract void SetUserPasswordHash(TUser user, string hashedPassword);

    protected abstract TUser CreateTestUser(string namePrefix = "", string email = "", string phoneNumber = "",
        bool lockoutEnabled = false, DateTimeOffset? lockoutEnd = default, bool useNamePrefixAsUserName = false);

    protected abstract Expression<Func<TUser, bool>> UserNameEqualsPredicate(string userName);

    protected abstract Expression<Func<TUser, bool>> UserNameStartsWithPredicate(string userName);

    protected abstract object CreateTestContext();

    /// <summary>
    /// Creates the user manager used for tests.
    /// </summary>
    /// <param name="context">The context that will be passed into the store, typically a db context.</param>
    /// <param name="services">The service collection to use, optional.</param>
    /// <param name="configureServices">Delegate used to configure the services, optional.</param>
    /// <returns>The user manager to use for tests.</returns>
    protected virtual TokenManager<IdentityStoreToken> CreateManager(object context = null, IServiceCollection services = null, Action<IServiceCollection> configureServices = null)
        => CreateTestServices(context, services, configureServices).GetService<TokenManager<IdentityStoreToken>>();

    protected virtual IServiceProvider CreateTestServices(object context = null, IServiceCollection services = null, Action<IServiceCollection> configureServices = null)
    {
        services ??= new ServiceCollection();
        context ??= CreateTestContext();
        SetupIdentityServices(services, context);
        configureServices?.Invoke(services);
        return services.BuildServiceProvider();
    }

    /// <summary>
    /// Test.
    /// </summary>
    /// <returns>Task</returns>
    [Fact]
    public async Task AccessTokenFormat()
    {
        var sp = CreateTestServices();
        var manager = sp.GetService<TokenManager<IdentityStoreToken>>();
        var userManager = sp.GetService<UserManager<TUser>>();
        var tokenService = sp.GetService<IUserTokenService<TUser>>();
        var validator = sp.GetService<IAccessTokenValidator>();
        var user = CreateTestUser();
        var userId = await userManager.GetUserIdAsync(user);
        IdentityResultAssert.IsSuccess(await userManager.CreateAsync(user));

        var claims = new[] {
            new Claim("custom", "value"),
            new Claim("custom2", "value"),
        };

        await userManager.AddClaimsAsync(user, claims);

        var token = await tokenService.GetAccessTokenAsync(user);
        Assert.NotNull(token);

        var principal = await validator.ValidateAsync(token);

        Assert.NotNull(principal);
        foreach (var cl in claims)
        {
            Assert.Contains(principal.Claims, c => c.Type == cl.Type && c.Value == cl.Value);
        }
        EnsureClaim(principal, "sub", userId);

        Assert.NotNull(principal.Claims.FirstOrDefault(c => c.Type == TokenClaims.Jti));
    }

    /// <summary>
    /// Test.
    /// </summary>
    /// <returns>Task</returns>
    [Fact]
    public async Task AccessTokenDuplicateClaimsFormat()
    {
        var sp = CreateTestServices();
        var manager = sp.GetService<TokenManager<IdentityStoreToken>>();
        var userManager = sp.GetService<UserManager<TUser>>();
        var tokenService = sp.GetService<IUserTokenService<TUser>>();
        var validator = sp.GetService<IAccessTokenValidator>();
        var user = CreateTestUser();
        var userId = await userManager.GetUserIdAsync(user);
        IdentityResultAssert.IsSuccess(await userManager.CreateAsync(user));

        var claims = new[] {
            new Claim("custom", "value"),
            new Claim("custom", "value2"),
            new Claim("custom2", "value"),
            new Claim("custom2", "value2"),
        };

        await userManager.AddClaimsAsync(user, claims);

        var token = await tokenService.GetAccessTokenAsync(user);
        Assert.NotNull(token);

        var principal = await validator.ValidateAsync(token);

        Assert.NotNull(principal);
        EnsureClaim(principal, "custom", "value2");
        EnsureClaim(principal, "custom2", "value2");
        EnsureClaim(principal, "sub", userId);

        Assert.NotNull(principal.Claims.FirstOrDefault(c => c.Type == TokenClaims.Jti));
    }

    /// <summary>
    /// Ensure that the principal has a claim with the name and value.
    /// </summary>
    /// <param name="principal"></param>
    /// <param name="name"></param>
    /// <param name="value"></param>
    protected void EnsureClaim(ClaimsPrincipal principal, string name, string value)
        => Assert.Contains(principal.Claims, c => c.Type == name && c.Value == value);

    /// <summary>
    /// Test.
    /// </summary>
    /// <returns></returns>
    [Fact]
    public async Task AccessTokensNotStoredByDefault()
    {
        var sp = CreateTestServices();
        var manager = sp.GetService<TokenManager<IdentityStoreToken>>();
        var userManager = sp.GetService<UserManager<TUser>>();
        var validator = sp.GetService<IAccessTokenValidator>();
        var tokenService = sp.GetService<IUserTokenService<TUser>>();
        var user = CreateTestUser();
        var userId = await userManager.GetUserIdAsync(user);
        IdentityResultAssert.IsSuccess(await userManager.CreateAsync(user));
        var token = await tokenService.GetAccessTokenAsync(user);
        Assert.NotNull(token);

        var principal = await validator.ValidateAsync(token);
        Assert.NotNull(principal);

        var jti = principal.Claims.FirstOrDefault(c => c.Type == TokenClaims.Jti)?.Value;
        Assert.NotNull(jti);

        // Verify the token is not in the store
        var tok = await manager.FindByIdAsync<IDictionary<string, string>>(jti);
        Assert.Null(tok);
    }

    /// <summary>
    /// Test.
    /// </summary>
    /// <returns>Task</returns>
    [Fact]
    public async Task CanRefreshTokensOnlyOnce()
    {
        var sp = CreateTestServices();
        var userManager = sp.GetService<UserManager<TUser>>();
        var tokenService = sp.GetService<IUserTokenService<TUser>>();
        var user = CreateTestUser();
        IdentityResultAssert.IsSuccess(await userManager.CreateAsync(user));

        var token = await tokenService.GetRefreshTokenAsync(user);
        Assert.NotNull(token);

        (var access, var refresh) = await tokenService.RefreshTokensAsync(token);
        Assert.NotNull(access);
        Assert.NotNull(refresh);

        // Second use should fail
        (var access2, var refresh2) = await tokenService.RefreshTokensAsync(token);

        Assert.Null(access2);
        Assert.Null(refresh2);

        // Using the new refresh token should work
        (access2, refresh2) = await tokenService.RefreshTokensAsync(refresh);
        Assert.NotNull(access2);
        Assert.NotNull(refresh2);
    }

    /// <summary>
    /// Test.
    /// </summary>
    /// <returns>Task</returns>
    [Fact]
    public async Task CanStoreAccessTokens()
    {
        var sp = CreateTestServices(configureServices:
            s =>
            {
                s.Configure<IdentityOptions>(o => o.TokenManager.StoreAccessTokens = true);
            });
        var manager = sp.GetService<TokenManager<IdentityStoreToken>>();
        var userManager = sp.GetService<UserManager<TUser>>();
        var validator = sp.GetService<IAccessTokenValidator>();
        var tokenService = sp.GetService<IUserTokenService<TUser>>();
        var user = CreateTestUser();
        var userId = await userManager.GetUserIdAsync(user);
        IdentityResultAssert.IsSuccess(await userManager.CreateAsync(user));

        var claims = new[] {
            new Claim("custom", "value"),
            new Claim("custom2", "value"),
        };

        await userManager.AddClaimsAsync(user, claims);

        var token = await tokenService.GetAccessTokenAsync(user);
        Assert.NotNull(token);

        var principal = await validator.ValidateAsync(token);

        Assert.NotNull(principal);
        foreach (var cl in claims)
        {
            Assert.Contains(principal.Claims, c => c.Type == cl.Type && c.Value == cl.Value);
        }
        EnsureClaim(principal, "sub", userId);

        var jti = principal.Claims.FirstOrDefault(c => c.Type == TokenClaims.Jti)?.Value;
        Assert.NotNull(jti);

        // Verify the token got serialized into the database
        var tok = await manager.FindByIdAsync<IDictionary<string, string>>(jti);
        Assert.NotNull(tok);

        // Make sure the payload is what we expect for the access token, with the security stamp
        var payload = tok.Payload as IDictionary<string, string>;
        Assert.NotNull(payload);
        Assert.NotNull(payload["AspNet.Identity.SecurityStamp"]);
    }

    private sealed class AccessTokenChecker : IAccessTokenDenyPolicy
    {
        private readonly TokenManager<IdentityStoreToken> _tokenManager;

        public AccessTokenChecker(TokenManager<IdentityStoreToken> tokenManager)
        {
            _tokenManager = tokenManager;
        }

        public async Task<bool> IsDeniedAsync(string tokenId)
        {
            // check for revocation is done by looking for a token record that has invalid status
            var storageToken = await _tokenManager.FindByIdAsync<object>(tokenId);
            return storageToken?.Status != TokenStatus.Active;
        }
    }

    /// <summary>
    /// Test.
    /// </summary>
    /// <returns>Task</returns>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task CannotRevokeAccessTokenDefault(bool storeTokens)
    {
        var sp = CreateTestServices(configureServices:
            s =>
            {
                s.Configure<IdentityOptions>(o => o.TokenManager.StoreAccessTokens = storeTokens);
            });
        var manager = sp.GetService<TokenManager<IdentityStoreToken>>();
        var userManager = sp.GetService<UserManager<TUser>>();
        var validator = sp.GetService<IAccessTokenValidator>();
        var tokenService = sp.GetService<IUserTokenService<TUser>>();
        var user = CreateTestUser();
        var userId = await userManager.GetUserIdAsync(user);
        IdentityResultAssert.IsSuccess(await userManager.CreateAsync(user));

        var token = await tokenService.GetAccessTokenAsync(user);
        Assert.NotNull(token);

        var principal = await validator.ValidateAsync(token);
        Assert.NotNull(principal);

        // Revoke the token and verify that by default nothing checks revocation
        var jti = principal.Claims.FirstOrDefault(c => c.Type == TokenClaims.Jti)?.Value;
        Assert.NotNull(jti);

        // Can only revoke if access tokens are stored
        Assert.Equal(storeTokens, await manager.RevokeAsync(jti));
        Assert.NotNull(await validator.ValidateAsync(token));
    }

    /// <summary>
    /// Test.
    /// </summary>
    /// <returns>Task</returns>
    [Fact]
    public async Task CanCheckAccessPerRequest()
    {
        var sp = CreateTestServices(configureServices:
            s =>
            {
                s.Configure<IdentityOptions>(o => o.TokenManager.StoreAccessTokens = true);
                s.AddSingleton<IAccessTokenDenyPolicy, AccessTokenChecker>();
            });
        var manager = sp.GetService<TokenManager<IdentityStoreToken>>();
        var userManager = sp.GetService<UserManager<TUser>>();
        var validator = sp.GetService<IAccessTokenValidator>();
        var tokenService = sp.GetService<IUserTokenService<TUser>>();
        var user = CreateTestUser();
        var userId = await userManager.GetUserIdAsync(user);
        IdentityResultAssert.IsSuccess(await userManager.CreateAsync(user));

        var token = await tokenService.GetAccessTokenAsync(user);
        Assert.NotNull(token);

        var principal = await validator.ValidateAsync(token);
        Assert.NotNull(principal);

        // Revoke the token and see if its rejected immediately
        var jti = principal.Claims.FirstOrDefault(c => c.Type == TokenClaims.Jti)?.Value;
        Assert.NotNull(jti);

        Assert.True(await manager.RevokeAsync(jti));
        Assert.Null(await validator.ValidateAsync(token));
    }

    /// <summary>
    /// Test.
    /// </summary>
    /// <returns>Task</returns>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task CanFindAllUserAccessTokensIfStored(bool storeTokens)
    {
        var sp = CreateTestServices(configureServices:
            s =>
            {
                s.Configure<IdentityOptions>(o => o.TokenManager.StoreAccessTokens = storeTokens);
            });
        var manager = sp.GetService<TokenManager<IdentityStoreToken>>();
        var userManager = sp.GetService<UserManager<TUser>>();
        var validator = sp.GetService<IAccessTokenValidator>();
        var tokenService = sp.GetService<IUserTokenService<TUser>>();
        var user = CreateTestUser();
        var userId = await userManager.GetUserIdAsync(user);
        IdentityResultAssert.IsSuccess(await userManager.CreateAsync(user));

        // Generate 2 access tokens
        var token1 = await tokenService.GetAccessTokenAsync(user);
        Assert.NotNull(token1);
        var principal1 = await validator.ValidateAsync(token1);
        Assert.NotNull(principal1);
        var jti1 = principal1.Claims.FirstOrDefault(c => c.Type == TokenClaims.Jti)?.Value;
        Assert.NotNull(jti1);

        var token2 = await tokenService.GetAccessTokenAsync(user);
        Assert.NotNull(token2);
        var principal2 = await validator.ValidateAsync(token2);
        Assert.NotNull(principal2);
        var jti2 = principal2.Claims.FirstOrDefault(c => c.Type == TokenClaims.Jti)?.Value;
        Assert.NotNull(jti2);

        Assert.NotSame(jti1, jti2);

        // Verify that we can get both tokens for the user only when they are stored
        var tokens = await manager.FindAsync(new TokenInfoFilter { Purpose = TokenPurpose.AccessToken, Subject = userId });
        Assert.Equal(storeTokens ? 2 : 0, tokens.Count());
        Assert.Equal(storeTokens, tokens.Contains(jti1));
        Assert.Equal(storeTokens, tokens.Contains(jti2));
    }

    /// <summary>
    /// Test.
    /// </summary>
    /// <returns>Task</returns>
    [Fact]
    public async Task CanRevokeAccessTokens()
    {
        var blockerOptions = new JtiBlockerOptions();
        var blocker = new JtiBlocker(Options.Create(blockerOptions));
        var sp = CreateTestServices(configureServices: s =>
        {
            s.AddSingleton<IAccessTokenDenyPolicy>(blocker);
        });
        var manager = sp.GetService<TokenManager< IdentityStoreToken>>();
        var userManager = sp.GetService<UserManager<TUser>>();
        var tokenService = sp.GetService<IUserTokenService<TUser>>();
        var validator = sp.GetService<IAccessTokenValidator>();
        var user = CreateTestUser();
        var userId = await userManager.GetUserIdAsync(user);
        IdentityResultAssert.IsSuccess(await userManager.CreateAsync(user));

        var token = await tokenService.GetAccessTokenAsync(user);
        Assert.NotNull(token);

        var principal = await validator.ValidateAsync(token);

        Assert.NotNull(principal);
        EnsureClaim(principal, "sub", userId);

        var jti = principal.Claims.FirstOrDefault(c => c.Type == TokenClaims.Jti)?.Value;
        Assert.NotNull(jti);

        // Revoke the access token and make sure it doesn't work
        blockerOptions.BlockedJti.Add(jti);
        Assert.Null(await validator.ValidateAsync(token));
    }

    /// <summary>
    /// Test.
    /// </summary>
    /// <returns>Task</returns>
    [Fact]
    public async Task ExpiredRefreshTokensFails()
    {
        var clock = new TestClock();
        var sp = CreateTestServices(configureServices: s => s.AddSingleton<ISystemClock>(clock));
        var manager = sp.GetService<TokenManager<IdentityStoreToken>>();
        var userManager = sp.GetService<UserManager<TUser>>();
        var tokenService = sp.GetService<IUserTokenService<TUser>>();
        var user = CreateTestUser();
        IdentityResultAssert.IsSuccess(await userManager.CreateAsync(user));

        var token = await tokenService.GetRefreshTokenAsync(user);
        Assert.NotNull(token);

        // Advance clock past expiration
        clock.UtcNow = DateTime.UtcNow.AddDays(2);

        (var access, var refresh) = await tokenService.RefreshTokensAsync(token);

        Assert.Null(access);
        Assert.Null(refresh);
    }

    /// <summary>
    /// Test.
    /// </summary>
    /// <returns>Task</returns>
    [Fact]
    public async Task CanPurgeExpiredTokens()
    {
        var clock = new TestClock();
        var sp = CreateTestServices(configureServices: s => s.AddSingleton<ISystemClock>(clock));
        var manager = sp.GetService<TokenManager<IdentityStoreToken>>();
        var userManager = sp.GetService<UserManager<TUser>>();
        var user = CreateTestUser();
        IdentityResultAssert.IsSuccess(await userManager.CreateAsync(user));
        var userId = await userManager.GetUserIdAsync(user);

        // Create a bunch of tokens some expired
        var expired1 = await manager.StoreAsync(new TokenInfo("id1", "f", userId, "p", "active") { Expiration = DateTimeOffset.UtcNow });
        var expired2 = await manager.StoreAsync(new TokenInfo("id2", "f", userId, "p", "active") { Expiration = DateTimeOffset.UtcNow });
        var token3 = await manager.StoreAsync(new TokenInfo("id3", "f", userId, "p", "active") { Expiration = DateTimeOffset.UtcNow.AddDays(1) });
        var token4 = await manager.StoreAsync(new TokenInfo("id4", "f", userId, "p", "active") { Expiration = DateTimeOffset.UtcNow.AddDays(1) });

        Assert.NotNull(await manager.FindByIdAsync<object>("id1"));
        Assert.NotNull(await manager.FindByIdAsync<object>("id2"));
        Assert.NotNull(await manager.FindByIdAsync<object>("id3"));
        Assert.NotNull(await manager.FindByIdAsync<object>("id4"));

        var purged = await manager.PurgeExpiredTokensAsync();

        // Make sure expired tokens are gone
        Assert.Equal(2, purged);
        Assert.Null(await manager.FindByIdAsync<object>("id1"));
        Assert.Null(await manager.FindByIdAsync<object>("id2"));
        Assert.NotNull(await manager.FindByIdAsync<object>("id3"));
        Assert.NotNull(await manager.FindByIdAsync<object>("id4"));
    }

    /// <summary>
    /// Test.
    /// </summary>
    /// <returns>Task</returns>
    [Fact]
    public async Task RevokedRefreshTokenFails()
    {
        var sp = CreateTestServices();
        var tokenService = sp.GetService<IUserTokenService<TUser>>();
        var userManager = sp.GetService<UserManager<TUser>>();
        var user = CreateTestUser();
        IdentityResultAssert.IsSuccess(await userManager.CreateAsync(user));

        var token = await tokenService.GetRefreshTokenAsync(user);
        Assert.NotNull(token);

        await tokenService.RevokeRefreshAsync(user, token);

        (var access, var refresh) = await tokenService.RefreshTokensAsync(token);

        Assert.Null(access);
        Assert.Null(refresh);
    }

    /// <summary>
    /// Test.
    /// </summary>
    /// <returns>Task</returns>
    [Fact]
    public async Task DeleteUserRemovesRefreshToken()
    {
        var sp = CreateTestServices();
        var tokenService = sp.GetService<IUserTokenService<TUser>>();
        var manager = sp.GetService<TokenManager<IdentityStoreToken>>();
        var userManager = sp.GetService<UserManager<TUser>>();
        var user = CreateTestUser();
        IdentityResultAssert.IsSuccess(await userManager.CreateAsync(user));

        var token = await tokenService.GetRefreshTokenAsync(user);
        Assert.NotNull(token);

        IdentityResultAssert.IsSuccess(await userManager.DeleteAsync(user));
        var userId = await userManager.GetUserIdAsync(user);
        Assert.Null(await userManager.FindByIdAsync(userId));
        Assert.Null(await manager.Store.FindAsync("", token, CancellationToken.None));
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

        var keyId = Guid.NewGuid().ToString();
        var data = new Dictionary<string, string>
        {
            ["kty"] = "oct",
            ["alg"] = "RS256",
            ["kid"] = keyId,
            ["k"] = publicKey
        };

        var privateJwk = new JsonWebKey("oct");
        privateJwk.Alg = "RS256";
        privateJwk.AdditionalData["k"] = privateKey;
        var builder = new JwtBuilder(JWSAlg.RS256, "i", privateJwk, "a", "s", data, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5));
        var jwt = await builder.CreateJwtAsync();

        var publicJwk = new JsonWebKey("oct");
        publicJwk.Alg = "RS256";
        publicJwk.AdditionalData["k"] = publicKey;

        var reader = new JwtReader(JWSAlg.RS256, "i", publicJwk, new string[] { "a" });
        var tok = await reader.ReadAsync(jwt);
        Assert.NotNull(tok);
    }
}
