// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Microsoft.Extensions.DependencyInjection;

namespace Microsoft.AspNetCore.Identity.Test;

public class IdentityBearerOptionsTest
{
    [Fact]
    public void CanReadConfig()
    {
        // An example of what the expected schema looks like
        // "Authentication": {
        //     "Schemes": {
        //       "Bearer": {
        //         "ValidAudiences": [ ],
        //         "ValidIssuer": "",
        //         "SigningKeys": [ { "Issuer": .., "Value": base64Key, "Length": 32 } ]
        //       }
        //     }
        //   }

        var services = new ServiceCollection();
        services.AddAuthentication();
        services.AddDefaultIdentityJwt<IdentityUser>(_ => { });

    }

}
