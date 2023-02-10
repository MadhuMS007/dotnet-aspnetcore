// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace TodoApi;

public sealed class AccessTokenDenyPolicy : IAccessTokenDenyPolicy
{
    private readonly UserManager<TodoUser> _userManager;
    private readonly JtiBlockerOptions _options;

    public AccessTokenDenyPolicy(UserManager<TodoUser> userManager, IOptions<JtiBlockerOptions> options)
    {
        _userManager = userManager;
        _options = options.Value;
    }

    public async Task<bool> IsDeniedAsync(TokenInfo token)
        => await _userManager.FindByIdAsync(token.Subject) == null ||
        _options.BlockedJti.Contains(token.Id);
}
