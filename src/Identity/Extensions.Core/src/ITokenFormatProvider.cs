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
    /// <param name="purpose">The token purpose.</param>
    /// <returns>The token info.</returns>
    Task<TokenInfo?> ReadTokenAsync(string token, string purpose);
}
