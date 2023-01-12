// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Identity;

/// <summary>
/// Used to filter token queries, any non null filter property must be an exact match for queries.
/// </summary>
public class TokenInfoFilter
{
    /// <summary>
    /// Gets or sets the Id to filter.
    /// </summary>
    public string? Id { get; set; }

    /// <summary>
    /// Gets or sets the format to filter.
    /// </summary>
    public string? Format { get; set; }

    /// <summary>
    /// Gets or sets the purpose to filter.
    /// </summary>
    public string? Purpose { get; set; }

    /// <summary>
    /// Gets or sets the subject to filter.
    /// </summary>
    public string? Subject { get; set; }

    /// <summary>
    /// Gets or sets the status to filter.
    /// </summary>
    public string? Status { get; set; }
}

/// <summary>
/// Provides an abstraction for a storage and management of tokens.
/// </summary>
public interface ITokenStore<TToken> : IDisposable where TToken : class
{
    /// <summary>
    /// Creates a new token instance that is not yet stored as an asynchronous operation.
    /// </summary>
    /// <param name="tokenInfo">The info to create a token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A <see cref="Task{TResult}"/> that represents the <see cref="IdentityResult"/> of the asynchronous query.</returns>
    Task<TToken> NewAsync(TokenInfo tokenInfo, CancellationToken cancellationToken);

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
    /// Return a <see cref="TokenInfo"/> from the token instance.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A <see cref="Task{TResult}"/> that represents the <see cref="TokenInfo"/> of the asynchronous query.</returns>
    Task<TokenInfo> GetTokenInfoAsync<TPayload>(TToken token, CancellationToken cancellationToken);

    /// <summary>
    /// Find tokens with the specified filter.
    /// </summary>
    /// <param name="filter">The filter to use.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A <see cref="Task{TResult}"/> with the token ids that match the filter.</returns>
    Task<IEnumerable<string>> FindAsync(TokenInfoFilter filter, CancellationToken cancellationToken);

    /// <summary>
    /// Find a token with the specified tokenId
    /// </summary>
    /// <param name="tokenId">The tokenId to find.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A <see cref="Task{TResult}"/> that result of the look up.</returns>
    Task<TToken?> FindByIdAsync(string tokenId, CancellationToken cancellationToken);

    /// <summary>
    /// Find a token with the specified purpose and value
    /// </summary>
    /// <param name="purpose">The purpose of the token.</param>
    /// <param name="value">The value of the token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A <see cref="Task{TResult}"/> that result of the look up.</returns>
    Task<TToken?> FindAsync(string purpose, string value, CancellationToken cancellationToken);

    /// <summary>
    /// Return the token format.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A <see cref="Task{TResult}"/> that represents the format of the asynchronous query.</returns>
    Task<string> GetFormatAsync(TToken token, CancellationToken cancellationToken);

    /// <summary>
    /// Set the format of a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="format">The format to set.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A <see cref="Task{TResult}"/> that represents the asynchronous query.</returns>
    Task SetFormatAsync(TToken token, string format, CancellationToken cancellationToken);

    /// <summary>
    /// Return the subject of a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A <see cref="Task{TResult}"/> that represents the subject of the asynchronous query.</returns>
    Task<string> GetSubjectAsync(TToken token, CancellationToken cancellationToken);

    /// <summary>
    /// Set the subject of a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="subject">The Subject to set.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A <see cref="Task{TResult}"/> that represents the asynchronous query.</returns>
    Task SetSubjectAsync(TToken token, string subject, CancellationToken cancellationToken);

    /// <summary>
    /// Return the status of a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A <see cref="Task{TResult}"/> that represents the status of the asynchronous query.</returns>
    Task<string> GetStatusAsync(TToken token, CancellationToken cancellationToken);

    /// <summary>
    /// Set the status of a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="status">The status to set.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A <see cref="Task{TResult}"/> that represents the asynchronous query.</returns>
    Task SetStatusAsync(TToken token, string status, CancellationToken cancellationToken);

    /// <summary>
    /// Return the expiration date of a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A <see cref="Task{TResult}"/> that represents the status of the asynchronous query.</returns>
    Task<DateTimeOffset> GetExpirationAsync(TToken token, CancellationToken cancellationToken);

    /// <summary>
    /// Set the expiration date of a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="expiration">The expiration date to set.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A <see cref="Task{TResult}"/> that represents the asynchronous query.</returns>
    Task SetExpirationAsync(TToken token, DateTimeOffset expiration, CancellationToken cancellationToken);

    /// <summary>
    /// Removes all expired tokens from the store.
    /// </summary>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A <see cref="Task{TResult}"/> that represents how many tokens were purged.</returns>
    Task<int> PurgeExpiredAsync(CancellationToken cancellationToken);
}
