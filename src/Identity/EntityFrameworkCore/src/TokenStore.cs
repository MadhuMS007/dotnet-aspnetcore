// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Linq;
using Microsoft.EntityFrameworkCore;

namespace Microsoft.AspNetCore.Identity.EntityFrameworkCore;

/// <summary>
/// Represents a new instance of a persistence store for the specified token types.
/// </summary>
/// <typeparam name="TToken">The type representing a token.</typeparam>
/// <typeparam name="TContext">The type of the data context class used to access the store.</typeparam>
public class TokenStore<TToken, TContext> : ITokenStore<TToken>
    where TToken : IdentityStoreToken
    where TContext : DbContext
{
    private bool _disposed;
    private readonly ITokenSerializer _serializer;

    /// <summary>
    /// Creates a new instance of the store.
    /// </summary>
    /// <param name="context">The context used to access the store.</param>
    /// <param name="serializer">The <see cref="ITokenSerializer"/> used to serialize tokens.</param>
    /// <param name="describer">The <see cref="IdentityErrorDescriber"/> used to describe store errors.</param>
    public TokenStore(TContext context, ITokenSerializer serializer, IdentityErrorDescriber? describer = null) 
    {
        Context = context ?? throw new ArgumentNullException(nameof(context));
        _serializer = serializer;
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
    public virtual Task<TToken> NewAsync(TokenInfo info, CancellationToken cancellationToken)
    {
        var token = (TToken)Activator.CreateInstance(typeof(TToken))!;
        token.Import(info);
        // Serialize the token payload if it exists.
        if (info.Payload != null)
        {
            token.Payload = _serializer.Serialize(info.Payload);
        }

        return Task.FromResult(token);
    }

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
    public async Task<TToken?> FindByIdAsync(string tokenId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        return await Tokens.FindAsync(new[] { tokenId }, cancellationToken);
    }

    /// <inheritdoc/>
    public Task<IEnumerable<string>> FindAsync(TokenInfoFilter filter, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        return Task.FromResult<IEnumerable<string>>(Tokens
            .Where(t =>
                (filter.Id == null || filter.Id == t.Id) &&
                (filter.Status == null || filter.Status == t.Status) &&
                (filter.Subject == null || filter.Subject == t.Subject) &&
                (filter.Purpose == null || filter.Purpose == t.Purpose) &&
                (filter.Format == null || filter.Format == t.Format))
            .Select(t => t.Id));
    }

    /// <inheritdoc/>
    public virtual async Task<TToken?> FindAsync(string purpose, string value, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        return await Tokens.SingleOrDefaultAsync(t => t.Purpose == purpose && t.Payload == value, cancellationToken);
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

    /// <inheritdoc/>
    public virtual Task<string> GetSubjectAsync(TToken token, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (token == null)
        {
            throw new ArgumentNullException(nameof(token));
        }
        return Task.FromResult(token.Subject);
    }

    /// <inheritdoc/>
    public virtual Task SetSubjectAsync(TToken token, string subject, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (token == null)
        {
            throw new ArgumentNullException(nameof(token));
        }
        token.Subject = subject;
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual Task<string> GetStatusAsync(TToken token, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (token == null)
        {
            throw new ArgumentNullException(nameof(token));
        }
        return Task.FromResult(token.Status);
    }

    /// <inheritdoc/>
    public virtual Task SetStatusAsync(TToken token, string status, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (token == null)
        {
            throw new ArgumentNullException(nameof(token));
        }
        token.Status = status;
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public Task<TokenInfo> GetTokenInfoAsync<TPayload>(TToken token, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (token == null)
        {
            throw new ArgumentNullException(nameof(token));
        }
        var info = new TokenInfo(token.Id, token.Format, token.Subject, token.Purpose, token.Status);
        info.Payload = _serializer.Deserialize<TPayload>(token.Payload);
        return Task.FromResult(info);
    }

    /// <inheritdoc/>
    public Task<string> GetFormatAsync(TToken token, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (token == null)
        {
            throw new ArgumentNullException(nameof(token));
        }
        return Task.FromResult(token.Format);
    }

    /// <inheritdoc/>
    public Task SetFormatAsync(TToken token, string format, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (token == null)
        {
            throw new ArgumentNullException(nameof(token));
        }
        token.Format = format;
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual Task<DateTimeOffset> GetExpirationAsync(TToken token, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (token == null)
        {
            throw new ArgumentNullException(nameof(token));
        }
        return Task.FromResult(token.Expiration);
    }

    /// <inheritdoc/>
    public virtual Task SetExpirationAsync(TToken token, DateTimeOffset expiration, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (token == null)
        {
            throw new ArgumentNullException(nameof(token));
        }
        token.Expiration = expiration;
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual async Task<int> PurgeExpiredAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();

        // AsEnumerable needed to force client side evaluation for sql lite
        var expiredTokens = Tokens.AsEnumerable().Where(t => t.Expiration < DateTimeOffset.UtcNow);
        Tokens.RemoveRange(expiredTokens);

        return await Context.SaveChangesAsync(cancellationToken);
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
