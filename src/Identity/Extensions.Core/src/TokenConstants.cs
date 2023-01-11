// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace Microsoft.AspNetCore.Identity;

/// <summary>
/// Constants for use for token status.
/// </summary>
public static class TokenStatus
{
    /// <summary>
    /// Represents an active valid token status.
    /// </summary>
    public const string Active = "active";

    /// <summary>
    /// Represents an inactive token status.
    /// </summary>
    public const string Inactive = "inactive";

    /// <summary>
    /// Represents a revoked token status.
    /// </summary>
    public const string Revoked = "revoked";
}

/// <summary>
/// Constants used to represent token purposes.
/// </summary>
public static class TokenPurpose
{
    /// <summary>
    /// Purpose for access tokens.
    /// </summary>
    public const string AccessToken = "access_token";

    /// <summary>
    /// Purpose for refresh tokens.
    /// </summary>
    public const string RefreshToken = "refresh_token";
}

/// <summary>
/// Constants used to represent token claims.
/// </summary>
public static class TokenClaims
{
    /// <summary>
    /// The Issuer for the token.
    /// </summary>
    public const string Issuer = "iss";

    /// <summary>
    /// The Subject for the token.
    /// </summary>
    public const string Subject = "sub";

    /// <summary>
    /// The intended audience for the token.
    /// </summary>
    public const string Audience = "aud";

    /// <summary>
    /// When the token expires.
    /// </summary>
    public const string Expires = "exp";

    /// <summary>
    /// Specifies when the token must not be accepted before.
    /// </summary>
    public const string NotBefore = "nbf";

    /// <summary>
    /// When the token was issued.
    /// </summary>
    public const string IssuedAt = "iat";

    /// <summary>
    /// The identifier for the token.
    /// </summary>
    public const string Jti = "jti";
}

/// <summary>
/// Constants used to represent token formats.
/// </summary>
public static class TokenFormat
{
    /// <summary>
    /// JWT format
    /// </summary>
    public const string JWT = "jwt";

    /// <summary>
    /// Single use redemption
    /// </summary>
    public const string Single = "single";
}
