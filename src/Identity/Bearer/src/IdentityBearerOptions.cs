// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Microsoft.AspNetCore.Authentication;

namespace Microsoft.AspNetCore.Identity;

/// <summary>
/// 
/// </summary>
public class BearerSchemeOptions : AuthenticationSchemeOptions
{
    // Move IdentityBearerOptions here
}

/// <summary>
/// 
/// </summary>
public class IdentityBearerOptions : AuthenticationSchemeOptions
{
    /// <summary>
    /// The Issuer for the token
    /// </summary>
    public string? Issuer { get; set; }

    /// <summary>
    /// The <see cref="SigningCredentials"/> to use.
    /// </summary>
    public JsonWebKey? SigningCredentials { get; set; }

    /// <summary>
    /// The list of valid audiences
    /// </summary>
    public IList<string> Audiences { get; set; } = new List<string>();
}
