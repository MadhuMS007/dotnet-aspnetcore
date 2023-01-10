// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Identity;

/// <summary>
/// Provides an abstraction for a serialization of tokens.
/// </summary>
public interface ITokenSerializer
{
    /// <summary>
    /// Serialize the value.
    /// </summary>
    /// <typeparam name="T"></typeparam>
    /// <param name="value"></param>
    /// <returns>The string representing the value.</returns>
    string Serialize<T>(T value);

    /// <summary>
    /// Deserialize an object from the specified serializedValue.
    /// </summary>
    /// <typeparam name="T"></typeparam>
    /// <param name="serializedValue"></param>
    /// <returns>The deserialiezd object.</returns>
    T? Deserialize<T>(string? serializedValue);
}
