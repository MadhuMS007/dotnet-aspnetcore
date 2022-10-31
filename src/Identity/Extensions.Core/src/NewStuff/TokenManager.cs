// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Identity.Core;
using Microsoft.Extensions.Logging;

namespace Microsoft.AspNetCore.Identity;

/// <summary>
/// 
/// </summary>
/// <typeparam name="TUser"></typeparam>
public interface ITokenStore<TUser> : IDisposable where TUser : class { }

/// <summary>
/// Provides the APIs for managing roles in a persistence store.
/// </summary>
/// <typeparam name="TUser">The type encapsulating a user.</typeparam>
public class TokenManager<TUser> : IDisposable where TUser : class
{
    private bool _disposed;

    /// <summary>
    /// The cancellation token used to cancel operations.
    /// </summary>
    protected virtual CancellationToken CancellationToken => CancellationToken.None;

    /// <summary>
    /// Constructs a new instance of <see cref="TokenManager{TUser}"/>.
    /// </summary>
    /// <param name="store">The persistence store the manager will operate over.</param>
    /// <param name="errors">The <see cref="IdentityErrorDescriber"/> used to provider error messages.</param>
    /// <param name="logger">The logger used to log messages, warnings and errors.</param>
    public TokenManager(ITokenStore<TUser> store,
        IdentityErrorDescriber errors,
        ILogger<TokenManager<TUser>> logger)
    {
        if (store == null)
        {
            throw new ArgumentNullException(nameof(store));
        }
        Store = store;
        ErrorDescriber = errors;
        Logger = logger;
    }

    /// <summary>
    /// Gets the persistence store this instance operates over.
    /// </summary>
    /// <value>The persistence store this instance operates over.</value>
    protected ITokenStore<TUser> Store { get; private set; }

    /// <summary>
    /// Gets the <see cref="ILogger"/> used to log messages from the manager.
    /// </summary>
    /// <value>
    /// The <see cref="ILogger"/> used to log messages from the manager.
    /// </value>
    public virtual ILogger Logger { get; set; }

    /// <summary>
    /// Gets the <see cref="IdentityErrorDescriber"/> used to provider error messages.
    /// </summary>
    /// <value>
    /// The <see cref="IdentityErrorDescriber"/> used to provider error messages.
    /// </value>
    public IdentityErrorDescriber ErrorDescriber { get; set; }

    /// <summary>
    /// Releases all resources used by the role manager.
    /// </summary>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Releases the unmanaged resources used by the role manager and optionally releases the managed resources.
    /// </summary>
    /// <param name="disposing">true to release both managed and unmanaged resources; false to release only unmanaged resources.</param>
    protected virtual void Dispose(bool disposing)
    {
        if (disposing && !_disposed)
        {
            Store.Dispose();
        }
        _disposed = true;
    }

    /// <summary>
    /// Throws if this class has been disposed.
    /// </summary>
    protected void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(GetType().Name);
        }
    }
}
