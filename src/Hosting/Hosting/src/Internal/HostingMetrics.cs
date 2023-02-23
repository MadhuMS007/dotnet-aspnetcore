// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics.Metrics;
using Microsoft.Extensions.Metrics;

namespace Microsoft.AspNetCore.Hosting;

internal class HostingMetrics : IDisposable
{
    private readonly Meter _meter;
    private readonly ObservableCounter<long> _totalRequestsCounter;
    private readonly ObservableUpDownCounter<long> _currentRequestsCounter;
    private readonly ObservableCounter<long> _failedRequestsCounter;

    public HostingMetrics(IMetricsFactory metricsFactory)
    {
        _meter = metricsFactory.CreateMeter("Microsoft.AspNetCore.Hosting");

        _totalRequestsCounter = _meter.CreateObservableCounter<long>(
            "total-requests",
            () => HostingEventSource.Log.TotalRequests,
            description: "Total Requests");

        _currentRequestsCounter = _meter.CreateObservableUpDownCounter<long>(
            "current-requests",
            () => HostingEventSource.Log.CurrentRequests,
            description: "Current Requests");

        _failedRequestsCounter = _meter.CreateObservableCounter<long>(
            "failed-requests",
            () => HostingEventSource.Log.FailedRequests,
            description: "Failed Requests");
    }

    public void Dispose()
    {
        _meter.Dispose();
    }

    public bool IsEnabled() => _totalRequestsCounter.Enabled || _currentRequestsCounter.Enabled || _failedRequestsCounter.Enabled;
}
