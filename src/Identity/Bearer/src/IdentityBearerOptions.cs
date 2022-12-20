// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.AspNetCore.Identity;

/// <summary>
/// 
/// </summary>
public class BearerSchemeOptions : AuthenticationSchemeOptions
{
    /// <summary>
    /// Gets or sets the parameters used to validate identity tokens.
    /// </summary>
    /// <remarks>Contains the types and definitions required for validating a token.</remarks>
    /// <exception cref="ArgumentNullException">if 'value' is null.</exception>
    public TokenValidationParameters TokenValidationParameters { get; set; } = new TokenValidationParameters();
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
    public SigningCredentials? SigningCredentials { get; set; }

    /// <summary>
    /// The list of valid audiences
    /// </summary>
    public IList<string> Audiences { get; set; } = new List<string>();
}
