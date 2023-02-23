// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics.Metrics;
using Microsoft.Extensions.Metrics;
using Microsoft.Extensions.Options;

namespace Microsoft.AspNetCore.Hosting.Abstractions.MetricsPrototype;

internal sealed class DefaultMetricsFactory : IMetricsFactory
{
    private readonly IOptions<MetricsOptions> _options;

    public DefaultMetricsFactory(IOptions<MetricsOptions> options)
    {
        _options = options;
    }

    public Meter CreateMeter(string name)
    {
        // TODO: Configure meter with default tags.
        return new Meter(name);
    }

    public Meter CreateMeter(MeterOptions options)
    {
        // TODO: Configure meter with default tags.
        return new Meter(options.Name, options.Version);
    }
}
