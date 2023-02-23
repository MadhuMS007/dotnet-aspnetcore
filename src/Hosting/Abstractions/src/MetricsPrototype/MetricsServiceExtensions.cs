// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Microsoft.AspNetCore.Hosting.Abstractions.MetricsPrototype;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Metrics;

namespace Microsoft.Extensions.DependencyInjection;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
#pragma warning disable RS0016 // Add public types and members to the declared API
public static class MetricsServiceExtensions
{
    public static IServiceCollection AddMetrics(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton<IMetricsFactory, DefaultMetricsFactory>();

        return services;
    }

    public static IServiceCollection AddMetrics(this IServiceCollection services, Action<MetricsOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddMetrics();
        services.Configure(configure);

        return services;
    }
}
#pragma warning restore RS0016 // Add public types and members to the declared API
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
