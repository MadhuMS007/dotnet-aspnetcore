// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Microsoft.AspNetCore.Authorization;

// TODO: remove to fix publicapi later
#if NETCOREAPP

/// <summary>
/// 
/// </summary>
public static class PermissionsExtensions
{
    /// <summary>
    /// 
    /// </summary>
    /// <param name="services"></param>
    /// <returns></returns>
    public static IServiceCollection AddPermissions(this IServiceCollection services)
    {
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IAuthorizationHandler, PermissionAuthorizationHandler>());
        services.TryAddSingleton<IUserPermissionChecker, ClaimPermissionChecker>();
        return services;
    }
}

/// <summary>
/// Specifies that the class or method that this attribute is applied to does requires a permission.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
public class RequirePermissionAttribute : Attribute, IAuthorizationRequirementData
{
    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="permission">The name of the required permission.</param>
    public RequirePermissionAttribute(string permission)
        => Permission = permission;

    /// <summary>
    /// The name of the required permission.
    /// </summary>
    public string Permission { get; }

    /// <inheritdoc/>
    public IEnumerable<IAuthorizationRequirement> GetRequirements()
        => new[] { new PermissionRequirement(Permission) };
}

/// <summary>
/// Represents a requirement for a particular permission.
/// </summary>
public class PermissionRequirement : IAuthorizationRequirement
{
    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="permission">The name of the required permission.</param>
    public PermissionRequirement(string permission)
        => Permission = permission;

    /// <summary>
    /// The name of the required permission.
    /// </summary>
    public string Permission { get; }
}

/// <summary>
/// Responsible for generating permissions for a user.
/// </summary>
public interface IAuthorizationPermissionHandler
{
    /// <summary>
    /// Adds any permissions a user possess to the set.
    /// </summary>
    /// <param name="user">The user.</param>
    /// <param name="permissions">The set of permissions to add to.</param>
    /// <returns>A task.</returns>
    Task AddPermissionsAsync(ClaimsPrincipal user, PermissionSet permissions);
}

/// <summary>
/// Represents a set of permissions
/// </summary>
public class PermissionSet : IEnumerable<string>
{
    private readonly HashSet<string> _permissions = new HashSet<string>();

    /// <summary>
    /// Grant a permission.
    /// </summary>
    /// <param name="permission">The permission to grant.</param>
    /// <returns>True if the permission was granted, false if it was already granted.</returns>
    public bool Grant(string permission)
        => _permissions.Add(permission);

    /// <summary>
    /// Revoke a permission
    /// </summary>
    /// <param name="permission">The permission to revoke.</param>
    /// <returns>True if the permission was revoked, false if it was not currently granted.</returns>
    public bool Revoke(string permission)
        => _permissions.Remove(permission);

    /// <summary>
    /// Checks if the permission is in the set.
    /// </summary>
    /// <param name="permission">The permission to bebe checked.</param>
    /// <returns>True if the permission has been granted.</returns>
    public bool Contains(string permission)
        => _permissions.Contains(permission);

    /// <summary>
    /// Checks if all the permissions are in this set.
    /// </summary>
    /// <param name="permissions">The permissions to be checked.</param>
    /// <returns>True if all the permissions have been granted.</returns>
    public bool Contains(IEnumerable<string> permissions)
    {
        foreach (var permission in permissions)
        {
            if (!Contains(permission))
            {
                return false;
            }
        }
        return true;
    }

    /// <inheritdoc/>
    public IEnumerator<string> GetEnumerator()
        => ((IEnumerable<string>)_permissions).GetEnumerator();

    /// <inheritdoc/>
    IEnumerator IEnumerable.GetEnumerator()
        => ((IEnumerable)_permissions).GetEnumerator();
}

/// <summary>
/// Responsible for determining if a user has a permission
/// </summary>
public interface IUserPermissionChecker
{
    /// <summary>
    /// Returns true if the user has the specified permission.
    /// </summary>
    /// <param name="user"></param>
    /// <param name="permission"></param>
    /// <returns></returns>
    Task<bool> HasPermissionAsync(ClaimsPrincipal user, string permission);
}

internal sealed class ClaimPermissionChecker : IUserPermissionChecker
{
    /// <summary>
    /// Expects a claim to be present for each permission.
    /// </summary>
    /// <param name="user">The user.</param>
    /// <param name="permission">The permission.</param>
    /// <returns>True if the user has the permissions.</returns>
    /// <exception cref="NotImplementedException"></exception>
    public Task<bool> HasPermissionAsync(ClaimsPrincipal user, string permission)
        => Task.FromResult(user.HasClaim(c => c.Type == permission));
}

internal sealed class PermissionAuthorizationHandler : IAuthorizationHandler
{
    private readonly IUserPermissionChecker _permissionChecker;

    public PermissionAuthorizationHandler(IUserPermissionChecker checker)
        => _permissionChecker = checker;

    public async Task HandleAsync(AuthorizationHandlerContext context)
    {
        //var permissions = new PermissionSet();
        //foreach (var handler in _permissionHandlers)
        //{
        //    await handler.AddPermissionsAsync(context.User, permissions).ConfigureAwait(false);
        //}

        // Find all of the permission requirements and succeed the ones we can
        foreach (var req in context.PendingRequirements)
        {
            var permissionReq = req as PermissionRequirement;
            if (permissionReq != null &&
                await _permissionChecker.HasPermissionAsync(context.User, permissionReq.Permission).ConfigureAwait(false))
            {
                context.Succeed(req);
            }
        }
    }
}
#endif
