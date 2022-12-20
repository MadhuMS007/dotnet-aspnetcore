// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Security.Claims;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Microsoft.AspNetCore.Authorization.Test;

public class PermissionTests
{
    private IAuthorizationService BuildAuthorizationService(Action<IServiceCollection> setupServices = null)
    {
        var services = new ServiceCollection();
        services.AddAuthorizationCore();
        services.AddLogging();
        services.AddOptions();
        services.AddPermissions();
        setupServices?.Invoke(services);
        return services.BuildServiceProvider().GetRequiredService<IAuthorizationService>();
    }

    [Fact]
    public async Task OnePermissionsGranted()
    {
        // Arrange
        var authorizationService = BuildAuthorizationService(services =>
            services.AddAuthorizationBuilder()
                .AddPolicy("Permission", policy =>
                    policy.RequirePermission("Permission1")));
        var user = new ClaimsPrincipal(new ClaimsIdentity(new Claim[] { new Claim("Permission1", ""), new Claim("Permission2", "") }));

        // Act
        var allowed = await authorizationService.AuthorizeAsync(user, "Permission");

        // Assert
        Assert.True(allowed.Succeeded);
    }

    [Fact]
    public async Task BothPermissionsGranted()
    {
        // Arrange
        var authorizationService = BuildAuthorizationService(services =>
            services.AddAuthorizationBuilder()
                .AddPolicy("Permission", policy =>
                    policy.RequirePermission("Permission1").RequirePermission("Permission2")));
        var user = new ClaimsPrincipal(new ClaimsIdentity(new Claim[] { new Claim("Permission1", ""), new Claim("Permission2", "") }));

        // Act
        var allowed = await authorizationService.AuthorizeAsync(user, "Permission");

        // Assert
        Assert.True(allowed.Succeeded);
    }

    [Fact]
    public async Task OnePermissionsMissingFails()
    {
        // Arrange
        var authorizationService = BuildAuthorizationService(services =>
            services.AddAuthorizationBuilder()
                .AddPolicy("Permission", policy =>
                    policy.RequirePermission("Permission1").RequirePermission("Permission3")));
        var user = new ClaimsPrincipal(new ClaimsIdentity(new Claim[] { new Claim("Permission1", ""), new Claim("Permission2", "") }));

        // Act
        var allowed = await authorizationService.AuthorizeAsync(user, "Permission");

        // Assert
        Assert.False(allowed.Succeeded);
    }

}
