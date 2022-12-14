// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Microsoft.EntityFrameworkCore;

namespace Microsoft.AspNetCore.Identity;

/// <summary>
/// 
/// </summary>
public class IdentityToken
{
    /// <summary>
    /// The userId for the owner of the token
    /// </summary>
    public string UserId { get; set; } = string.Empty;

    /// <summary>
    /// The purpose for the token
    /// </summary>
    public string Purpose { get; set; } = string.Empty;

    /// <summary>
    /// The value for the token
    /// </summary>
    public string Value { get; set; } = string.Empty;

    /// <summary>
    /// Get or set how long this token is valid until.
    /// </summary>
    public DateTimeOffset ValidUntil { get; set; }

    /// <summary>
    /// Get or set whether the token is revoked.
    /// </summary>
    public bool Revoked { get; set; }

    /// <summary>
    /// A random value that must change whenever a token is persisted to the store
    /// </summary>
    public virtual string? ConcurrencyStamp { get; set; } = Guid.NewGuid().ToString();
}

/// <summary>
/// Provides an abstraction for a storage and management of tokens.
/// </summary>
public interface ITokenStore<TToken> : IDisposable where TToken : class
{
    /// <summary>
    /// Creates a new token in a store as an asynchronous operation.
    /// </summary>
    /// <param name="token">The token to create in the store.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A <see cref="Task{TResult}"/> that represents the <see cref="IdentityResult"/> of the asynchronous query.</returns>
    Task<IdentityResult> CreateAsync(TToken token, CancellationToken cancellationToken);

    /// <summary>
    /// Updates a token in a store as an asynchronous operation.
    /// </summary>
    /// <param name="token">The token to update in the store.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A <see cref="Task{TResult}"/> that represents the <see cref="IdentityResult"/> of the asynchronous query.</returns>
    Task<IdentityResult> UpdateAsync(TToken token, CancellationToken cancellationToken);

    /// <summary>
    /// Deletes a token from the store as an asynchronous operation.
    /// </summary>
    /// <param name="token">The token to delete from the store.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A <see cref="Task{TResult}"/> that represents the <see cref="IdentityResult"/> of the asynchronous query.</returns>
    Task<IdentityResult> DeleteAsync(TToken token, CancellationToken cancellationToken);

    /// <summary>
    /// Find a token with the specified purpose and value
    /// </summary>
    /// <param name="purpose">The purpose of the token.</param>
    /// <param name="value">The value of the token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A <see cref="Task{TResult}"/> that result of the look up.</returns>
    Task<TToken?> FindAsync(string purpose, string value, CancellationToken cancellationToken);
}

/// <summary>
/// Represents a new instance of a persistence store for the specified token types.
/// </summary>
/// <typeparam name="TToken">The type representing a token.</typeparam>
/// <typeparam name="TContext">The type of the data context class used to access the store.</typeparam>
public class TokenStore<TToken, TContext> : ITokenStore<TToken>
    where TToken : IdentityToken
    where TContext : DbContext
{
    private bool _disposed;

    /// <summary>
    /// Creates a new instance of the store.
    /// </summary>
    /// <param name="context">The context used to access the store.</param>
    /// <param name="describer">The <see cref="IdentityErrorDescriber"/> used to describe store errors.</param>
    public TokenStore(TContext context, IdentityErrorDescriber? describer = null) 
    {
        Context = context ?? throw new ArgumentNullException(nameof(context));
        ErrorDescriber = describer ?? new IdentityErrorDescriber();
    }

    // REVIEW
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Trimming", "IL2091:Target generic argument does not satisfy 'DynamicallyAccessedMembersAttribute' in target method or type. The generic parameter of the source method or type does not have matching annotations.", Justification = "<Pending>")]
    private DbSet<TToken> Tokens { get { return Context.Set<TToken>(); } }

    /// <summary>
    /// Gets the database context for this store.
    /// </summary>
    public virtual TContext Context { get; private set; }

    /// <summary>
    /// Gets the <see cref="IdentityErrorDescriber"/> used to provider error messages.
    /// </summary>
    /// <value>
    /// The <see cref="IdentityErrorDescriber"/> used to provider error messages.
    /// </value>
    public IdentityErrorDescriber ErrorDescriber { get; set; }

    /// <inheritdoc/>
    public virtual async Task<IdentityResult> CreateAsync(TToken token, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (token == null)
        {
            throw new ArgumentNullException(nameof(token));
        }
        Context.Add(token);
        await SaveChanges(cancellationToken);
        return IdentityResult.Success;
    }

    /// <inheritdoc/>
    public virtual async Task<IdentityResult> DeleteAsync(TToken token, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (token == null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        Context.Remove(token);
        try
        {
            await SaveChanges(cancellationToken);
        }
        catch (DbUpdateConcurrencyException)
        {
            return IdentityResult.Failed(ErrorDescriber.ConcurrencyFailure());
        }
        return IdentityResult.Success;
    }

    /// <inheritdoc/>
    public virtual async Task<TToken?> FindAsync(string purpose, string value, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        return await Tokens.SingleOrDefaultAsync(t => t.Purpose == purpose && t.Value == value, cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async Task<IdentityResult> UpdateAsync(TToken token, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (token == null)
        {
            throw new ArgumentNullException(nameof(token));
        }

        Context.Attach(token);
        token.ConcurrencyStamp = Guid.NewGuid().ToString();
        Context.Update(token);
        try
        {
            await SaveChanges(cancellationToken);
        }
        catch (DbUpdateConcurrencyException)
        {
            return IdentityResult.Failed(ErrorDescriber.ConcurrencyFailure());
        }
        return IdentityResult.Success;
    }

    /// <summary>
    /// Gets or sets a flag indicating if changes should be persisted after CreateAsync, UpdateAsync and DeleteAsync are called.
    /// </summary>
    /// <value>
    /// True if changes should be automatically persisted, otherwise false.
    /// </value>
    public bool AutoSaveChanges { get; set; } = true;

    /// <summary>Saves the current store.</summary>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
    protected Task SaveChanges(CancellationToken cancellationToken)
        => AutoSaveChanges ? Context.SaveChangesAsync(cancellationToken) : Task.CompletedTask;

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

    /// <summary>
    /// Dispose the store
    /// </summary>
    public void Dispose()
        => _disposed = true;
}
