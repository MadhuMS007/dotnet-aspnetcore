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
}
