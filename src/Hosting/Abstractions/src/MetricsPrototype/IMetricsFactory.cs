// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics.Metrics;

namespace Microsoft.Extensions.Metrics;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
#pragma warning disable RS0016 // Add public types and members to the declared API
public sealed class MetricsOptions
{
    public string? ContainerId { get; set; }
    public IDictionary<string, string> DefaultTags { get; } = new Dictionary<string, string>();
}

public sealed class MeterOptions
{
    public required string Name { get; set; }
    public string? Version { get; set; }
}

public interface IMetricsFactory
{
    Meter CreateMeter(string name);
    Meter CreateMeter(MeterOptions options);
}
#pragma warning restore RS0016 // Add public types and members to the declared API
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
