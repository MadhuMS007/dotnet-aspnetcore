// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace Microsoft.AspNetCore.Identity;

/// <summary>
/// Represents all the options you can use to configure the identity endpoints.
/// </summary>
public class EndpointOptions
{
    /// <summary>
    /// The identity endpoint prefix, "/identity"
    /// </summary>
    public string IdentityRouteGroup { get; set; } = $"/identity";

    /// <summary>
    /// The register users endpoint, "/register";
    /// </summary>
    public string RegisterEndpoint { get; set; } = "/register";

    /// <summary>
    /// The confirm email endpoint, "/confirmEmail";
    /// </summary>
    public string ConfirmEmailEndpoint { get; set; } = $"/confirmEmail";

    /// <summary>
    /// The login endpoint, /login";
    /// </summary>
    public string LoginEndpoint { get; set; } = $"/login";

    /// <summary>
    /// The logout endpoint, /logout";
    /// </summary>
    public string LogoutEndpoint { get; set; } = $"/logout";

    /// <summary>
    /// The refresh token endpoint, "/refresh";
    /// </summary>
    public string RefreshEndpoint { get; set; } = $"/refresh";

    /// <summary>
    /// The identity manage subgroup, "/manage"
    /// </summary>
    public string IdentityManageSubgroup { get; set; } = $"/manage";

    /// <summary>
    /// The authenticator get endpoint, "/authenticator";
    /// </summary>
    public string AuthenticatorGetEndpoint { get; set; } = $"/authenticator";

    /// <summary>
    /// The verify authenticator post endpoint, "/verifyAuthenticator";
    /// </summary>
    public string VerifyAuthenticatorPostEndpoint { get; set; } = $"/verifyAuthenticator";
}
