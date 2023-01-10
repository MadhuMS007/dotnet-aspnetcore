// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Linq;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Microsoft.AspNetCore.Identity;

/// <summary>
/// Constants for use for token status.
/// </summary>
public static class TokenStatus
{
    /// <summary>
    /// Represents an active valid token status.
    /// </summary>
    public const string Active = "active";

    /// <summary>
    /// Represents an inactive token status.
    /// </summary>
    public const string Inactive = "inactive";

    /// <summary>
    /// Represents a revoked token status.
    /// </summary>
    public const string Revoked = "revoked";
}

/// <summary>
/// Constants used to represent token purposes.
/// </summary>
public static class TokenPurpose
{
    /// <summary>
    /// Purpose for access tokens.
    /// </summary>
    public const string AccessToken = "access_token";

    /// <summary>
    /// Purpose for refresh tokens.
    /// </summary>
    public const string RefreshToken = "refresh_token";
}

/// <summary>
/// Constants used to represent token claims.
/// </summary>
public static class TokenClaims
{
    /// <summary>
    /// The Issuer for the token.
    /// </summary>
    public const string Issuer = "iss";

    /// <summary>
    /// The Subject for the token.
    /// </summary>
    public const string Subject = "sub";

    /// <summary>
    /// The intended audience for the token.
    /// </summary>
    public const string Audience = "aud";

    /// <summary>
    /// When the token expires.
    /// </summary>
    public const string Expires = "exp";

    /// <summary>
    /// Specifies when the token must not be accepted before.
    /// </summary>
    public const string NotBefore = "nbf";

    /// <summary>
    /// When the token was issued.
    /// </summary>
    public const string IssuedAt = "iat";

    /// <summary>
    /// The identifier for the token.
    /// </summary>
    public const string Jti = "jti";
}

/// <summary>
/// Constants used to represent token formats.
/// </summary>
public static class TokenFormat
{
    /// <summary>
    /// JWT format
    /// </summary>
    public const string JWT = "jwt";

    /// <summary>
    /// Single use redemption
    /// </summary>
    public const string Single = "single";
}

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
    where TToken : IdentityStoreToken
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
            b.HasMany<TToken>().WithOne().HasForeignKey(ur => ur.Subject).IsRequired();
        });

        builder.Entity<TToken>(b =>
        {
            b.HasIndex(t => new { t.Purpose, t.Payload }).HasDatabaseName("TokenPurposeValueIndex");
            b.ToTable("AspNetTokens");
            b.Property(r => r.ConcurrencyStamp).IsConcurrencyToken();

            // REVIEW should we cap the purpose/value lengths?
            b.Property(u => u.Purpose).HasMaxLength(256);
            b.Property(u => u.Payload).HasMaxLength(256);
        });

        builder.Entity<KeyInfo>(b =>
        {
            b.ToTable("AspNetKeys");

            // REVIEW should we cap the purpose/value lengths?
            b.Property(u => u.ProviderId).HasMaxLength(256);
            b.Property(u => u.Format).HasMaxLength(256);
        });
    }
}

/// <summary>
/// Represents a new instance of a persistence store for the specified token types.
/// </summary>
/// <typeparam name="TToken">The type representing a token.</typeparam>
/// <typeparam name="TContext">The type of the data context class used to access the store.</typeparam>
public class TokenStore<TToken, TContext> : ITokenStore<TToken>, IKeyStore
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
    public TokenStore(TContext context, ITokenSerializer? serializer = null, IdentityErrorDescriber? describer = null) 
    {
        Context = context ?? throw new ArgumentNullException(nameof(context));
        _serializer = serializer ?? JsonTokenSerizlier.Instance;
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
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Trimming", "IL2087:Target parameter argument does not satisfy 'DynamicallyAccessedMembersAttribute' in call to target method. The generic parameter of the source method or type does not have matching annotations.", Justification = "<Pending>")]
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

    async Task<IdentityResult> IKeyStore.AddAsync(string keyId, string providerId, string format, string data, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        var key = new KeyInfo()
        {
            Id = keyId,
            ProviderId = providerId,
            Format = format,
            Data = data,
            Created = DateTimeOffset.UtcNow
        };
        Context.Add(key);
        await SaveChanges(cancellationToken);
        return IdentityResult.Success;
    }

    async Task<KeyInfo?> IKeyStore.FindByIdAsync(string keyId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();

        return await Context.Set<KeyInfo>().FindAsync(new object?[] { keyId }, cancellationToken: cancellationToken);
    }

    /// <inheritdoc/>
    async Task<IdentityResult> IKeyStore.RemoveAsync(string keyId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();

        var key = Context.Set<KeyInfo>().Find(keyId);
        if (key == null)
        {
            return IdentityResult.Success;
        }
        Context.Remove(key);
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
}
