// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Text;
using Microsoft.Extensions.DependencyInjection;

namespace Microsoft.AspNetCore.Identity.Test;

public class KeyRingTest
{
    [Fact]
    public async Task CanAddKey()
    {
        var services = new ServiceCollection();
        var key1Bytes = Encoding.UTF8.GetBytes("secretkey1");
        var key2Bytes = Encoding.UTF8.GetBytes("secretkey2");
        var key1 = new BaseKey(key1Bytes, DateTimeOffset.UtcNow.AddDays(1));
        var key2 = new BaseKey(key2Bytes, DateTimeOffset.UtcNow.AddDays(1));
        services.AddOptions<KeyRingOptions>("kr1").Configure(o => o.KeySources.Add(new ActualKeySource(key1)));
        services.AddOptions<KeyRingOptions>("kr2").Configure(o => o.KeySources.Add(new ActualKeySource(key2)));
        services.AddOptions<KeyRingOptions>("kr12").Configure(o =>
        {
            o.KeySources.Add(new ActualKeySource(key1));
            o.KeySources.Add(new ActualKeySource(key2));
        });
        services.AddSingleton<KeyRingManager>();
        var sp = services.BuildServiceProvider();

        var keyManager = sp.GetService<KeyRingManager>();
        var kr1 = await keyManager.GetKeyRingAsync("kr1");
        Assert.Contains(key1, kr1.GetAllKeys());
        var kr2 = await keyManager.GetKeyRingAsync("kr2");
        Assert.Contains(key2, kr2.GetAllKeys());
        var kr12 = await keyManager.GetKeyRingAsync("kr12");
        var allKeys = kr12.GetAllKeys();
        Assert.Contains(key1, allKeys);
        Assert.Contains(key2, allKeys);
    }
}
