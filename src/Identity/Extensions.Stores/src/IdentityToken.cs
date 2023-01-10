// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;

namespace Microsoft.AspNetCore.Identity;

/// <summary>
/// 
/// </summary>
public class IdentityToken
{
    /// <summary>
    /// Default constructor.
    /// </summary>
    public IdentityToken()
    {
        Id = Guid.NewGuid().ToString();
    }

    /// <summary>
    /// Import the token info into this instance.
    /// </summary>
    /// <param name="info">The token info to import.</param>
    public IdentityToken(TokenInfo info)
        => Import(info);

    /// <summary>
    /// Import the token info into this instance.
    /// </summary>
    /// <param name="info">The token info to import.</param>
    public void Import(TokenInfo info)
    {
        Id = info.Id;
        Subject = info.Subject;
        Status = info.Status;
        Purpose = info.Purpose;
        Expiration = info.Expiration.GetValueOrDefault();
        Created = info.Created ?? DateTimeOffset.UtcNow;
    }

    /// <summary>
    /// The Id for the token.
    /// </summary>
    public string Id { get; set; } = default!;

    /// <summary>
    /// The subject for the token.
    /// </summary>
    public string Subject { get; set; } = default!;

    /// <summary>
    /// The purpose for the token.
    /// </summary>
    public string Purpose { get; set; } = default!;

    /// <summary>
    /// The payload for the token.
    /// </summary>
    public string? Payload { get; set; }

    /// <summary>
    /// Get or set when this token was created.
    /// </summary>
    public DateTimeOffset? Created { get; set; }

    /// <summary>
    /// Get or set when this token expires.
    /// </summary>
    public DateTimeOffset Expiration { get; set; }

    /// <summary>
    /// Get or set the token status, i.e. active, revoked.
    /// </summary>
    public string Status { get; set; } = default!;

    /// <summary>
    /// A random value that must change whenever a token is persisted to the store
    /// </summary>
    public virtual string? ConcurrencyStamp { get; set; } = Guid.NewGuid().ToString();
}

