// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Microsoft.Extensions.Logging;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Identity;

/// <summary>
/// Abstraction for managing user sign in policy.
/// </summary>
/// <typeparam name="TUser"></typeparam>
public interface ISignInPolicy<TUser> where TUser : class
{
    /// <summary>
    /// Checks whether a specified user can sign in, a non null result shuld be treated as an error..
    /// </summary>
    /// <param name="user">The user whose sign-in status should be returned.</param>
    /// <returns>
    /// The task object representing the asynchronous operation, containing a null
    /// if the specified user can sign-in, otherwise the sign-in status that should be returned.
    /// </returns>
    public Task<SignInResult?> CanSignInAsync(TUser user);

    /// <summary>
    /// Check if the <paramref name="user"/> has two factor enabled.
    /// </summary>
    /// <param name="user"></param>
    /// <returns>
    /// The task object representing the asynchronous operation containing true if the user has two factor enabled.
    /// </returns>
    public Task<bool> IsTwoFactorEnabledAsync(TUser user);

    /// <summary>
    /// Attempt to sign in a user with the specified password and tfaCode.
    /// </summary>
    /// <param name="userName">The user name.</param>
    /// <param name="password">The password.</param>
    /// <param name="tfaCode">The optional two factor code.</param>
    /// <returns>The <see cref="SignInResult"/> and the user if successful, null otherwise.</returns>
    public Task<(SignInResult, TUser?)> PasswordSignInAsync(string userName, string password, string? tfaCode);
}
