// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Identity;

/// <summary>
/// Represents a key used for signing.
/// </summary>
public class KeyInfo
{
    /// <summary>
    /// Get or set the Id for the key.
    /// </summary>
    public string Id { get; set; } = Guid.NewGuid().ToString();

    /// <summary>
    /// Get or set the provider defined format for the key, i.e. version
    /// </summary>
    public string Format { get; set; } = default!;

    /// <summary>
    /// Get or set the string specifying the id of the provider for the key.
    /// </summary>
    public string ProviderId { get; set; } = default!;

    /// <summary>
    /// Get or set the data representing the key.
    /// </summary>
    public string Data { get; set; } = default!;

    /// <summary>
    /// Get or set when the key was created.
    /// </summary>
    public DateTimeOffset Created { get; set; }
}
