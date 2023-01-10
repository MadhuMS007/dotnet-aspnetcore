// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Globalization;
using System.Linq.Expressions;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Identity.InMemory.Test;
using Microsoft.AspNetCore.Identity.Test;
using Microsoft.Extensions.DependencyInjection;

namespace Microsoft.AspNetCore.Identity.InMemory;

public class InMemoryTokenStoreTest : TokenManagerSpecificationTestBase<PocoUser>, IClassFixture<InMemoryUserStoreTest.Fixture>
{
    private readonly string Issuer = "dotnet-user-jwts";
    private readonly string Audience = "<audience>";

    protected override void AddUserStore(IServiceCollection services, object context = null)
        => services.AddSingleton<IUserStore<PocoUser>>((InMemoryUserStore<PocoUser>)context);

    protected override void AddTokenStore(IServiceCollection services, object context = null)
        => services.AddSingleton((ITokenStore<IdentityToken>)context);

    protected override void SetUserPasswordHash(PocoUser user, string hashedPassword)
        => user.PasswordHash = hashedPassword;

    protected override PocoUser CreateTestUser(string namePrefix = "", string email = "", string phoneNumber = "",
        bool lockoutEnabled = false, DateTimeOffset? lockoutEnd = default, bool useNamePrefixAsUserName = false)
    {
        return new PocoUser
        {
            UserName = useNamePrefixAsUserName ? namePrefix : string.Format(CultureInfo.InvariantCulture, "{0}{1}", namePrefix, Guid.NewGuid()),
            Email = email,
            PhoneNumber = phoneNumber,
            LockoutEnabled = lockoutEnabled,
            LockoutEnd = lockoutEnd
        };
    }

    protected override Expression<Func<PocoUser, bool>> UserNameEqualsPredicate(string userName) => u => u.UserName == userName;

    protected override Expression<Func<PocoUser, bool>> UserNameStartsWithPredicate(string userName) => u => u.UserName.StartsWith(userName, StringComparison.Ordinal);

    protected override object CreateTestContext()
        => new InMemoryTokenStore<PocoUser, PocoRole>();

    /// <summary>
    /// Creates the user manager used for tests.
    /// </summary>
    /// <param name="context">The context that will be passed into the store, typically a db context.</param>
    /// <param name="services">The service collection to use, optional.</param>
    /// <param name="configureServices">Delegate used to configure the services, optional.</param>
    /// <returns>The user manager to use for tests.</returns>
    protected override TokenManager<PocoUser, IdentityToken> CreateManager(object context = null, IServiceCollection services = null, Action<IServiceCollection> configureServices = null)
    {
        if (services == null)
        {
            services = new ServiceCollection();
        }
        if (context == null)
        {
            context = CreateTestContext();
        }
        SetupIdentityServices(services, context);
        configureServices?.Invoke(services);
        return services.BuildServiceProvider().GetService<TokenManager<PocoUser, IdentityToken>>();
    }

    /// <summary>
    /// Test.
    /// </summary>
    /// <returns>Task</returns>
    [Fact]
    public async Task CanStoreAccessTokensInMemory()
    {
        var manager = CreateManager();
        var user = CreateTestUser();
        IdentityResultAssert.IsSuccess(await manager.UserManager.CreateAsync(user));

        var claims = new[] {
            new Claim("custom", "value"),
            new Claim("custom2", "value"),
        };

        await manager.UserManager.AddClaimsAsync(user, claims);

        var token = await manager.GetAccessTokenAsync(user);
        Assert.NotNull(token);

        var principal = await manager.ValidateAccessTokenAsync(token);

        Assert.NotNull(principal);
        foreach (var cl in claims)
        {
            Assert.Contains(principal.Claims, c => c.Type == cl.Type && c.Value == cl.Value);
        }
        EnsureClaim(principal, "iss", Issuer);
        EnsureClaim(principal, "aud", Audience);
        EnsureClaim(principal, "sub", user.Id);

        var jti = principal.Claims.FirstOrDefault(c => c.Type == TokenClaims.Jti)?.Value;
        Assert.NotNull(jti);

        // Verify the token got serialized into the database
        var store = (InMemoryTokenStore<PocoUser, PocoRole>)manager.Store;

        var tok = store._tokens[jti];
        Assert.NotNull(tok);

        // Make sure we can json deserialize the payload too
        var payload = JsonSerializer.Deserialize<IDictionary<string, string>>(tok.Payload);
        Assert.NotNull(payload);
        Assert.NotNull(payload["AspNet.Identity.SecurityStamp"]);
    }
}
