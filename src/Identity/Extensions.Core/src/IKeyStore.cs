// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Identity;

/// <summary>
/// Provides an abstraction for a storage and management of tokens.
/// </summary>
public interface IKeyStore : IDisposable
{
    /// <summary>
    /// Add a new key in the store as an asynchronous operation.
    /// </summary>
    /// <param name="keyId">The string used to identify the key.</param>
    /// <param name="providerId">The string used to identify the key provider.</param>
    /// <param name="format">The string used to identify the format for the key.</param>
    /// <param name="data">The string containing the key data.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A <see cref="Task{TResult}"/> that represents the <see cref="IdentityResult"/> of the asynchronous query.</returns>
    Task<IdentityResult> AddAsync(string keyId, string providerId, string format, string data, CancellationToken cancellationToken);

    /// <summary>
    /// Get a key from the store as an asynchronous operation.
    /// </summary>
    /// <param name="keyId">The key to retrieve from the store.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A <see cref="Task{TResult}"/> that represents the <see cref="IdentityResult"/> of the asynchronous query.</returns>
    Task<KeyInfo?> FindByIdAsync(string keyId, CancellationToken cancellationToken);

    /// <summary>
    /// Remove a key from the store as an asynchronous operation.
    /// </summary>
    /// <param name="keyId">The key to remove from the store.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A <see cref="Task{TResult}"/> that represents the <see cref="IdentityResult"/> of the asynchronous query.</returns>
    Task<IdentityResult> RemoveAsync(string keyId, CancellationToken cancellationToken);
}
