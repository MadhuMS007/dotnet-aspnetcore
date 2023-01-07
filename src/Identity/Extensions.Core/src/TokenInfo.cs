// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Identity;

/// <summary>
/// Represents token information and source for a token record.
/// </summary>
public class TokenInfo
{
    /// <summary>
    /// Creates a new instance of <see cref="TokenInfo"/>
    /// </summary>
    public TokenInfo(string subject, string purpose, string payload)
    {
        Subject = subject;
        Purpose = purpose;
        Payload = payload;
    }

    /// <summary>
    /// Gets or sets the creation date for the token.
    /// </summary>
    public DateTimeOffset? Created { get; set; }

    /// <summary>
    /// Gets or sets the expiration date for the token.
    /// </summary>
    public DateTimeOffset? Expiration { get; set; }

    /// <summary>
    /// Gets or sets the token payload.
    /// </summary>
    public string Payload { get; set; }

    /// <summary>
    /// Gets or sets a string representing the token purpose, i.e. Refresh or Access
    /// </summary>
    public string Purpose { get; set; }

    /// <summary>
    /// Gets or sets the subject of the token, i.e. user id.
    /// </summary>
    public string Subject { get; set; }

    /// <summary>
    /// Gets or sets the status of the token, i.e. active, revoked.
    /// </summary>
    public string? Status { get; set; }
}
