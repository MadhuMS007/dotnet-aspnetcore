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
    /// The Id for the token.
    /// </summary>
    public string Id { get; set; } = Guid.NewGuid().ToString();

    /// <summary>
    /// The userId for the owner of the token.
    /// </summary>
    public string UserId { get; set; } = default!;

    /// <summary>
    /// The purpose for the token.
    /// </summary>
    public string Purpose { get; set; } = default!;

    /// <summary>
    /// The value for the token.
    /// </summary>
    public string Value { get; set; } = default!;

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

