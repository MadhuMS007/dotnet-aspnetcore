// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.ComponentModel.DataAnnotations;

namespace Microsoft.AspNetCore.Identity.Bearer;

/// <summary>
/// DTO for the register endpoint, username, password
/// </summary>
public class RegisterEndpointInfo
{
    /// <summary>
    /// The user name.
    /// </summary>
    [Required]
    public string Username { get; set; } = default!;

    /// <summary>
    /// The password
    /// </summary>
    [Required]
    public string Password { get; set; } = default!;

    /// <summary>
    /// The email for the user.
    /// </summary>
    public string Email { get; set; } = default!;
}

/// <summary>
/// DTO for the login endpoint, username, password, tfacode
/// </summary>
public class LoginEndpointInfo
{
    /// <summary>
    /// The user name.
    /// </summary>
    [Required]
    public string Username { get; set; } = default!;

    /// <summary>
    /// The password
    /// </summary>
    [Required]
    public string Password { get; set; } = default!;

    /// <summary>
    /// When true, cookies will be returned instead of tokens.
    /// </summary>
    public bool CookieMode { get; set; }

    /// <summary>
    /// Optional two factor code needed if enabled for the user.
    /// </summary>
    public string? TfaCode { get; set; }
}

/// <summary>
/// DTO for the logout endpoint
/// </summary>
public class LogoutEndpointInfo
{
    /// <summary>
    /// When true, the login cookie will be cleared instead of invalidating an access token.
    /// </summary>
    public bool CookieMode { get; set; }
}

/// <summary>
/// Represents information needed for an external user.
/// </summary>
public class ExternalUserInfo
{
    /// <summary>
    /// The user name.
    /// </summary>
    [Required]
    public string Username { get; set; } = default!;

    /// <summary>
    /// The external provider key for the user.
    /// </summary>
    [Required]
    public string ProviderKey { get; set; } = default!;
}

/// <summary>
/// DTO representing the response returned from the token endpoint
/// </summary>
/// <param name="AccessToken"></param>
/// <param name="RefreshToken"></param>
public record AuthTokens(string AccessToken, string RefreshToken);

/// <summary>
/// DTO representing a token.
/// </summary>
public class TokenData
{
    /// <summary>
    /// The token.
    /// </summary>
    [Required]
    public string Token { get; set; } = default!;
}

/// <summary>
/// DTO representing a verification token, used for confirming emails, 2fa, authenticator
/// </summary>
public class VerificationToken
{
    /// <summary>
    /// THe user id being confirmed.
    /// </summary>
    public string UserId { get; set; } = default!;

    /// <summary>
    /// The confirmation code.
    /// </summary>
    [Required]
    public string Token { get; set; } = default!;
}

/// <summary>
/// DTO representing authenticator app information.
/// </summary>
public class AuthenticatorInfo
{
    /// <summary>
    /// The Uri for the authenticator.
    /// </summary>
    public string Uri { get; set; } = default!;

    /// <summary>
    /// The authenticator key.
    /// </summary>
    public string Key { get; set; } = default!;
}

