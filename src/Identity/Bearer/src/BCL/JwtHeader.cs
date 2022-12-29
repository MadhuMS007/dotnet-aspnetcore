// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections;
using System.Diagnostics.CodeAnalysis;

namespace Microsoft.AspNetCore.Identity;

internal sealed class JwtHeader : IDictionary<string, string>
{
    public string this[string key] { get => Headers[key]; set => Headers[key] = value; }

    /// <summary>
    /// Constructor, alg is required.
    /// </summary>
    /// <param name="alg"></param>
    public JwtHeader(string alg) => Alg = alg;

    public JwtHeader(IDictionary<string, string> headers)
    {
        if (!headers.ContainsKey("alg"))
        {
            throw new ArgumentException("alg must be specified.", nameof(headers));
        }
        Headers = headers;
    }

    /// <summary>
    /// The actual headers.
    /// </summary>
    public IDictionary<string, string> Headers { get; } = new Dictionary<string, string>();

    /// <summary>
    /// Maps to the Headers["alg"] representing the Algorithm for the JWT.
    /// </summary>
    public string Alg
    {
        get => Headers["alg"];
        private set => Headers["alg"] = value;
    }

    /// <summary>
    /// Maps to the Headers["typ"] representing the Type of the JWT.
    /// </summary>
    public string Type
    {
        get => Headers["typ"];
        set => Headers["typ"] = value;
    }

    public string ContentType
    {
        get => Headers["cty"];
        set => Headers["cty"] = value;
    }

    public ICollection<string> Keys => Headers.Keys;

    public ICollection<string> Values => Headers.Values;

    public int Count => Headers.Count;

    public bool IsReadOnly => Headers.IsReadOnly;

    public void Add(string key, string value)
        => Headers.Add(key, value);

    public void Add(KeyValuePair<string, string> item)
        => Headers.Add(item);

    public void Clear()
        => Headers.Clear();

    public bool Contains(KeyValuePair<string, string> item)
        => Headers.Contains(item);

    public bool ContainsKey(string key)
        => Headers.ContainsKey(key);

    public void CopyTo(KeyValuePair<string, string>[] array, int arrayIndex)
        => Headers.CopyTo(array, arrayIndex);

    public IEnumerator<KeyValuePair<string, string>> GetEnumerator()
        => Headers.GetEnumerator();

    public bool Remove(string key)
        => Headers.Remove(key);

    public bool Remove(KeyValuePair<string, string> item)
        => Headers.Remove(item);

    public bool TryGetValue(string key, [MaybeNullWhen(false)] out string value)
        => Headers.TryGetValue(key, out value);

    IEnumerator IEnumerable.GetEnumerator()
        => ((IEnumerable)Headers).GetEnumerator();
}

