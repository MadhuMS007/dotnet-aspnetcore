// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace Microsoft.AspNetCore.Identity;

using System;

/// <summary>
/// Used for identity entity framework options
/// </summary>
public class IdentityEntityFrameworkOptions
{
    /// <summary>
    /// The concrete DbContext type to use.
    /// </summary>
    public Type? DbContextType { get; set; }
}
