// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Identity;

/// <summary>
/// Options for managing the token manager and storage..
/// </summary>
public class TokenManagerOptions
{
    /// <summary>
    /// Maps token formats to the ITokenFormatProvider that can create and validate tokens.
    /// </summary>
    public IDictionary<string, ITokenFormatProvider> FormatProviderMap{ get; set; } = new Dictionary<string, ITokenFormatProvider>();

    /// <summary>
    /// Maps token purposes to a token format (i.e. AccessToken -> JWT, RefreshToken -> Refresh)
    /// </summary>
    public IDictionary<string, string> PurposeFormatMap { get; set; } = new Dictionary<string, string>();
}

/// <summary>
/// Responsible for creating and validating token formats.
/// </summary>
public interface ITokenFormatProvider
{
    /// <summary>
    /// 
    /// </summary>
    /// <param name="data">The token data to serialize.</param>
    /// <returns>The serialized token.</returns>
    Task<string> SerializeAsync(IDictionary<string, string> data);
}
