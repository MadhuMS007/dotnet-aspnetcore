// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Identity;

/// <summary>
/// Responsible for creating and validating token formats.
/// </summary>
public interface ITokenFormatProvider
{
    /// <summary>
    /// Responsible for serializing the token payload
    /// </summary>
    ITokenSerializer PayloadSerializer { get; }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="token">The token info to create.</param>
    /// <returns>The token.</returns>
    Task<string> CreateTokenAsync(TokenInfo token);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="token">The token to read.</param>
    /// <returns>The token info.</returns>
    Task<TokenInfo?> ReadTokenAsync(string token);
}

/// <summary>
/// Responsible for configuration of token formats.
/// </summary>
public class TokenFormatOptions
{
    /// <summary>
    /// The key ring to use for signing.
    /// </summary>
    public string? SigningKeyRing { get; set; }

    /// <summary>
    /// The key ring to use for validation.
    /// </summary>
    public string? ValidationKeyRing { get; set; }

    /// <summary>
    /// Issuer for this token.
    /// </summary>
    public string Issuer { get; set; }

    /// <summary>
    /// If true, the token should be data protected.
    /// </summary>
    public bool UseDataProtection { get; set; }
}
