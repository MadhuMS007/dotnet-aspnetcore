// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Microsoft.AspNetCore.Identity;

/// <summary>
/// Represents a user's device, i.e. browser, phone, TV
/// </summary>
internal sealed class IdentityDevice
{
    /// <summary>
    /// The Id for the device.
    /// </summary>
    public string Id { get; set; } = Guid.NewGuid().ToString();

    /// <summary>
    /// The userId for the user who owns this device.
    /// </summary>
    public string UserId { get; set; } = string.Empty;

    /// <summary>
    /// The name of the device.
    /// </summary>
    public string Name { get; set; } = string.Empty;
}

/// <summary>
/// Base class for the Entity Framework database context used for identity.
/// </summary>
/// <typeparam name="TUser">The type of user objects.</typeparam>
/// <typeparam name="TRole">The type of role objects.</typeparam>
/// <typeparam name="TToken">The type of token objects.</typeparam>
/// <typeparam name="TKey">The type of the primary key for users and roles.</typeparam>
/// <typeparam name="TUserClaim">The type of the user claim object.</typeparam>
/// <typeparam name="TUserRole">The type of the user role object.</typeparam>
/// <typeparam name="TUserLogin">The type of the user login object.</typeparam>
/// <typeparam name="TRoleClaim">The type of the role claim object.</typeparam>
/// <typeparam name="TUserToken">The type of the user token object.</typeparam>
public abstract class IdentityDbContext<TUser, TRole, TToken, TKey, TUserClaim, TUserRole, TUserLogin, TRoleClaim, TUserToken> : IdentityDbContext<TUser, TRole, TKey, TUserClaim, TUserRole, TUserLogin, TRoleClaim, TUserToken>
    where TUser : IdentityUser<TKey>
    where TRole : IdentityRole<TKey>
    where TToken : IdentityToken
    where TKey : IEquatable<TKey>
    where TUserClaim : IdentityUserClaim<TKey>
    where TUserRole : IdentityUserRole<TKey>
    where TUserLogin : IdentityUserLogin<TKey>
    where TRoleClaim : IdentityRoleClaim<TKey>
    where TUserToken : IdentityUserToken<TKey>
{
    /// <summary>
    /// Initializes a new instance of the class.
    /// </summary>
    /// <param name="options">The options to be used by a <see cref="DbContext"/>.</param>
    public IdentityDbContext(DbContextOptions options) : base(options) { }

    /// <summary>
    /// Initializes a new instance of the class.
    /// </summary>
    protected IdentityDbContext() { }

    /// <summary>
    /// Gets or sets the <see cref="DbSet{TEntity}"/> of tokens.
    /// </summary>
    // REVIEW!!
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Trimming", "IL2091:Target generic argument does not satisfy 'DynamicallyAccessedMembersAttribute' in target method or type. The generic parameter of the source method or type does not have matching annotations.", Justification = "<Pending>")]
    public virtual DbSet<TToken> Tokens { get; set; } = default!;

    /// <summary>
    /// Configures the schema needed for the identity framework.
    /// </summary>
    /// <param name="builder">
    /// The builder being used to construct the model for this context.
    /// </param>
    // REVIEW!!
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Trimming", "IL2091:Target generic argument does not satisfy 'DynamicallyAccessedMembersAttribute' in target method or type. The generic parameter of the source method or type does not have matching annotations.", Justification = "<Pending>")]
    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<TUser>(b =>
        {
            b.HasMany<TToken>().WithOne().HasForeignKey(ur => ur.UserId).IsRequired();
        });

        builder.Entity<TToken>(b =>
        {
            // REVIEW: is this correct for index?
            b.HasIndex(t => t.Purpose + t.Value).HasDatabaseName("TokenPurposeValueIndex");
            b.ToTable("AspNetTokens");
            b.Property(r => r.ConcurrencyStamp).IsConcurrencyToken();

            // REVIEW should we cap the purpose/value lengths?
            b.Property(u => u.Purpose).HasMaxLength(256);
            b.Property(u => u.Value).HasMaxLength(256);
        });
    }
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
