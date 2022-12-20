// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authorization;

// TODO: remove to fix publicapi later
#if NETCOREAPP || NET462
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
    /// Returns a set of a permissions that the user possess.
    /// </summary>
    /// <param name="user">The user.</param>
    /// <returns>A set of a permissions that the user possess.</returns>
    Task<string> GetPermissionsAsync(ClaimsPrincipal user);
}
#endif
