// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics.Metrics;
using Microsoft.Extensions.Metrics;

namespace Microsoft.AspNetCore.Hosting.Fakes;

public class TestMetricsFactory : IMetricsFactory
{
    private readonly List<Meter> _meters = new List<Meter>();

    public IReadOnlyList<Meter> Meters => _meters;

    public Meter CreateMeter(string name)
    {
        var meter = new Meter(name);
        _meters.Add(meter);
        return meter;
    }

    public Meter CreateMeter(MeterOptions options)
    {
        var meter = new Meter(options.Name, options.Version);
        _meters.Add(meter);
        return meter;
    }
}
