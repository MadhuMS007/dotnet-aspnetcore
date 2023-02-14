// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.ComponentModel.DataAnnotations;

namespace Microsoft.AspNetCore.Identity.Bearer;

/// <summary>
/// Username/Password.
/// </summary>
public class PasswordLoginInfo
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
/// DTO representing a refresh token.
/// </summary>
public class RefreshToken
{
    /// <summary>
    /// The refresh token.
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

