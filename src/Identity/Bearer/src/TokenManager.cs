// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Microsoft.AspNetCore.Identity;

/// <summary>
/// Provides the APIs for managing tokens in a persistence store.
/// </summary>
/// <typeparam name="TToken">The type encapsulating a token.</typeparam>
public class TokenManager<TToken> : IDisposable
    where TToken : class
{
    private bool _disposed;

    /// <summary>
    /// The cancellation token used to cancel operations.
    /// </summary>
    protected internal virtual CancellationToken CancellationToken => CancellationToken.None;

    /// <summary>
    /// Constructs a new instance of <see cref="TokenManager{TToken}"/>.
    /// </summary>
    /// <param name="identityOptions">The options which configure the identity system.</param>
    /// <param name="store"></param>
    /// <param name="errors">The <see cref="IdentityErrorDescriber"/> used to provider error messages.</param>
    /// <param name="logger">The logger used to log messages, warnings and errors.</param>
    /// <exception cref="ArgumentNullException"></exception>
    /// <exception cref="InvalidOperationException"></exception>
    public TokenManager(
        IOptions<IdentityOptions> identityOptions,
        ITokenStore<TToken> store,
        IdentityErrorDescriber errors,
        ILogger<TokenManager<TToken>> logger)
    {
        Options = identityOptions.Value.TokenManager;
        Store = store ?? throw new ArgumentNullException(nameof(store));
        ErrorDescriber = errors;
        Logger = logger;
    }

    /// <summary>
    /// Gets the persistence store this instance operates over.
    /// </summary>
    /// <value>The persistence store this instance operates over.</value>
    protected internal ITokenStore<TToken> Store { get; }

    /// <summary>
    /// Gets the <see cref="ILogger"/> used to log messages from the manager.
    /// </summary>
    /// <value>
    /// The <see cref="ILogger"/> used to log messages from the manager.
    /// </value>
    public virtual ILogger Logger { get; set; }

    /// <summary>
    /// The <see cref="TokenManagerOptions"/>.
    /// </summary>
    public TokenManagerOptions Options { get; set; }

    /// <summary>
    /// Gets the <see cref="IdentityErrorDescriber"/> used to provider error messages.
    /// </summary>
    /// <value>
    /// The <see cref="IdentityErrorDescriber"/> used to provider error messages.
    /// </value>
    public IdentityErrorDescriber ErrorDescriber { get; set; }

    /// <summary>
    /// Releases all resources.
    /// </summary>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Find a token by its id.
    /// </summary>
    /// <param name="tokenId">The token id.</param>
    /// <returns>The <see cref="TokenInfo"/> representing the token</returns>
    public virtual async Task<TokenInfo?> FindByIdAsync<TPayload>(string tokenId)
    {
        var tok = await Store.FindByIdAsync(tokenId, CancellationToken).ConfigureAwait(false);
        if (tok == null)
        {
            return null;
        }
        return await Store.GetTokenInfoAsync<TPayload>(tok, CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Find all token ids that match the specified filter.
    /// </summary>
    /// <param name="filter">The filter to use to find tokens.</param>
    /// <returns>The matching tokens id.</returns>
    public virtual Task<IEnumerable<string>> FindAsync(TokenInfoFilter filter)
        => Store.FindAsync(filter, CancellationToken);

    /// <summary>
    /// Revokes a token.
    /// </summary>
    /// <param name="tokenId">The token id to revoke.</param>
    /// <returns>The true if a token was revoked.</returns>
    public virtual async Task<bool> RevokeAsync(string tokenId)
    {
        var tok = await Store.FindByIdAsync(tokenId, CancellationToken).ConfigureAwait(false);
        if (tok == null)
        {
            return false;
        }

        await Store.SetStatusAsync(tok, TokenStatus.Revoked, CancellationToken).ConfigureAwait(false);
        var result = await Store.UpdateAsync(tok, CancellationToken).ConfigureAwait(false);
        return result.Succeeded;
    }

    /// <summary>
    /// Removes all expired tokens from the store
    /// </summary>
    /// <returns></returns>
    public virtual Task<int> PurgeExpiredTokensAsync()
        // TODO: Should add a filter to specify token purpose, etc?
        => Store.PurgeExpiredAsync(CancellationToken);

    /// <summary>
    /// Store a new token instance with the specified token info
    /// </summary>
    /// <param name="info">The <see cref="TokenInfo"/> for the token.</param>
    /// <returns></returns>
    public virtual async Task<TToken> StoreAsync(TokenInfo info)
    {
        // TODO: make internal?
        var tok = await Store.NewAsync(info, CancellationToken).ConfigureAwait(false);
        await Store.CreateAsync(tok, CancellationToken);
        return tok;
    }

    /// <summary>
    /// Check if the token status is valid. Defaults to only active token status.
    /// </summary>
    /// <param name="status">The token status.</param>
    /// <returns>true if the token is should be allowed.</returns>
    protected virtual bool CheckTokenStatus(string status)
        => status == TokenStatus.Active;

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
