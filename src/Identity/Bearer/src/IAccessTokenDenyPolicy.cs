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
    /// <param name="token">The <see cref="TokenInfo"/> for the token.</param>
    /// <returns>True if the access token should be denied.</returns>
    Task<bool> IsDeniedAsync(TokenInfo token);
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
    /// <param name="token"></param>
    /// <returns></returns>
    public Task<bool> IsDeniedAsync(TokenInfo token)
        => Task.FromResult(_options.BlockedJti.Contains(token.Id));
}
