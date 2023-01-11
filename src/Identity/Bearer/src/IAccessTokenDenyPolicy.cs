// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Microsoft.Extensions.Options;

namespace Microsoft.AspNetCore.Identity;

/// <summary>
/// Determines if an access token should be denied.
/// </summary>
public interface IAccessTokenDenyPolicy
{
    /// <summary>
    /// Determines if an access token should be denied.
    /// </summary>
    /// <param name="tokenId">The id of the access token.</param>
    /// <returns>True if the access token should be denied.</returns>
    Task<bool> IsDeniedAsync(string tokenId);
}

/// <summary>
/// 
/// </summary>
public class JtiBlockerOptions
{
    /// <summary>
    /// 
    /// </summary>
    public HashSet<string> BlockedJti { get; } = new HashSet<string>();
}

/// <summary>
/// 
/// </summary>
public class JtiBlocker : IAccessTokenDenyPolicy
{
    private readonly JtiBlockerOptions _options;

    /// <summary>
    /// 
    /// </summary>
    /// <param name="options"></param>
    public JtiBlocker(IOptions<JtiBlockerOptions> options)
        => _options = options.Value;

    /// <summary>
    /// 
    /// </summary>
    /// <param name="tokenId"></param>
    /// <returns></returns>
    public Task<bool> IsDeniedAsync(string tokenId)
        => Task.FromResult(_options.BlockedJti.Contains(tokenId));
}
