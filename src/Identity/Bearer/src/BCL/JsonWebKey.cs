// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace Microsoft.AspNetCore.Identity;

/// <summary>
/// https://www.rfc-editor.org/rfc/rfc7517
/// </summary>
public sealed class JsonWebKey
{
    /// <summary>
    /// 
    /// </summary>
    /// <param name="kty"></param>
    public JsonWebKey(string kty) => Kty = kty;

    /// <summary>
    /// 
    /// </summary>
    public IDictionary<string, string> AdditionalData { get; } = new Dictionary<string, string>();

    /// <summary>
    /// 
    /// </summary>
    public string? Alg { get; set; }

    /// <summary>
    /// 
    /// </summary>
    public string? Kid { get; set; }

    /// <summary>
    /// 
    /// </summary>
    public IList<string>? KeyOps { get; set; }

    /// <summary>
    /// 
    /// </summary>
    public string Kty { get; set; }

    /// <summary>
    /// 
    /// </summary>
    public string? Use { get; set; }

    /// <summary>
    /// 
    /// </summary>
    public string? X5c { get; set; }

    /// <summary>
    /// 
    /// </summary>
    public string? X5t { get; set; }

    /// <summary>
    /// 
    /// </summary>
    public string? X5tS256 { get; set; }

    /// <summary>
    /// 
    /// </summary>
    public string? X5u { get; set; }

    //public string Crv { get; set; }
    //public string D { get; set; }
    //public string E { get; set; }
    //public string Dp { get; set; }
    //public string Dq { get; set; }
    //public string K { get; set; }
    //public string N { get; set; }
    //public string P { get; set; }
    //public string Q { get; set; }
    //public string Qi { get; set; }
    //public string Y { get; set; }
}
