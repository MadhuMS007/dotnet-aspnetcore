// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace Microsoft.AspNetCore.Identity;

/// <summary>
/// Represents all the options you can use to configure the cookies middleware used by the identity system.
/// </summary>
public class IdentityConstants
{
    /// <summary>
    /// The scheme used to identify application authentication cookies.
    /// </summary>
    public static readonly string ApplicationScheme = ApplicationSchemeName;

    /// <summary>
    /// The scheme used to identify application authentication cookies.
    /// </summary>
    public const string ApplicationSchemeName = "Identity.Application";

    /// <summary>
    /// The scheme used to identify external authentication cookies.
    /// </summary>
    public static readonly string ExternalScheme = ExternalSchemeName;

    /// <summary>
    /// The scheme used to identify external authentication cookies.
    /// </summary>
    public const string ExternalSchemeName = "Identity.External";

    /// <summary>
    /// The scheme used to identify Two Factor authentication cookies for saving the Remember Me state.
    /// </summary>
    public static readonly string TwoFactorRememberMeScheme = TwoFactorRememberMeSchemeName;

    /// <summary>
    /// The scheme used to identify Two Factor authentication cookies for saving the Remember Me state.
    /// </summary>
    public const string TwoFactorRememberMeSchemeName = "Identity.TwoFactorRememberMe";

    /// <summary>
    /// The scheme used to identify Two Factor authentication cookies for round tripping user identities.
    /// </summary>
    public static readonly string TwoFactorUserIdScheme = TwoFactorUserIdSchemeName;

    /// <summary>
    /// The scheme used to identify Two Factor authentication cookies for round tripping user identities.
    /// </summary>
    public const string TwoFactorUserIdSchemeName = "Identity.TwoFactorUserId";

    /// <summary>
    /// The scheme used to identify bearer authentication token.
    /// </summary>
    public const string BearerScheme = "Identity.Bearer";

    /// <summary>
    /// The scheme used to identify bearer cookie.
    /// </summary>
    public const string BearerCookieScheme = "Identity.Bearer.Cookie";
}
