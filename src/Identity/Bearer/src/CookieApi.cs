// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Globalization;
using System.Linq;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Bearer;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes extensions for mapping bearer token endpoints.
/// </summary>
public static class CookieApi
{
    /// <summary>
    /// Setup various bearer token routes under "/users".
    /// </summary>
    /// <typeparam name="TUser"></typeparam>
    /// <param name="routes"></param>
    /// <returns></returns>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Trimming", "IL2026:Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code", Justification = "<Pending>")]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("AOT", "IL3050:Calling members annotated with 'RequiresDynamicCodeAttribute' may break functionality when AOT compiling.", Justification = "<Pending>")]
    public static RouteGroupBuilder MapIdentityCookies<TUser>(this IEndpointRouteBuilder routes) where TUser : class, new()
    {
        var options = routes.ServiceProvider.GetRequiredService<IOptions<IdentityOptions>>().Value.Endpoints;

        var group = routes.MapGroup(options.IdentityRouteGroup).MapGroup(options.IdentityCookieRouteGroup);

        // TODO: add to options?
        group.WithTags("Identity", "Users");

        // group.WithParameterValidation(typeof(UserInfo), typeof(ExternalUserInfo));

        group.MapPost(options.RegisterEndpoint, async Task<Results<Ok, ValidationProblem>> (PasswordLoginInfo newUser, UserManager<TUser> userManager) =>
        {
            var user = new TUser();
            await userManager.SetUserNameAsync(user, newUser.Username);
            var result = await userManager.CreateAsync(user, newUser.Password);

            if (result.Succeeded)
            {
                return TypedResults.Ok();
            }

            return TypedResults.ValidationProblem(result.Errors.ToDictionary(e => e.Code, e => new[] { e.Description }));
        });

        group.MapPost(options.LoginEndpoint, async Task<Results<BadRequest, SignInHttpResult>> (PasswordLoginInfo userInfo, IUserClaimsPrincipalFactory<TUser> claimsFactory, ISignInPolicy<TUser> signInPolicy) =>
        {
            // TODO: Remember me? use new SignInPolicy
            // TODO: this should return different status (mfa etc)
            (var result, var user) = await signInPolicy.PasswordSignInAsync(userInfo.Username, userInfo.Password, userInfo.TfaCode);
            if (!result.Succeeded || user is null)
            {
                return TypedResults.BadRequest();
            }

            // TODO: directly use IClaimsPrincipalfactory?
            return TypedResults.SignIn(await claimsFactory.CreateAsync(user),
                properties: null, // IsPersistent would go here
                authenticationScheme: IdentityConstants.BearerCookieScheme);
        });

        group.MapPost(options.ConfirmEmailEndpoint, async Task<Results<BadRequest, Ok>> (VerificationToken code, UserManager<TUser> userManager) =>
        {
            if (code.Token is null || code.UserId is null)
            {
                return TypedResults.BadRequest();
            }

            var user = await userManager.FindByIdAsync(code.UserId);
            if (user is null)
            {
                return TypedResults.BadRequest();
            }

            var decodedCode = Encoding.UTF8.GetString(AspNetCore.WebUtilities.WebEncoders.Base64UrlDecode(code.Token));
            var result = await userManager.ConfirmEmailAsync(user, decodedCode);
            if (result.Succeeded)
            {
                return TypedResults.Ok();
            }

            // REVIEw Should this return an error message?
            return TypedResults.BadRequest();
        });

        // Protect manage section
        var manageGroup = group.MapGroup(options.IdentityManageSubgroup).RequireAuthorization();
        manageGroup.WithTags("Users", "Manage");

        manageGroup.MapPost(options.LogoutEndpoint, Results<BadRequest, SignOutHttpResult> () =>
            TypedResults.SignOut(authenticationSchemes: new[] { IdentityConstants.BearerCookieScheme }));

        manageGroup.MapGet(options.AuthenticatorGetEndpoint, async Task<Results<BadRequest, Ok<AuthenticatorInfo>>> (UserManager<TUser> userManager, HttpContext request) =>
        {
            var user = await userManager.GetUserAsync(request.User);
            if (user is null)
            {
                return TypedResults.BadRequest();
            }

            // Load the authenticator key & QR code URI to display on the form
            var unformattedKey = await userManager.GetAuthenticatorKeyAsync(user);
            if (string.IsNullOrEmpty(unformattedKey))
            {
                await userManager.ResetAuthenticatorKeyAsync(user);
                unformattedKey = await userManager.GetAuthenticatorKeyAsync(user);
            }
            var userName = await userManager.GetUserNameAsync(user);

            return TypedResults.Ok(new AuthenticatorInfo
            {
                Uri = GenerateQrCodeUri(userName!, unformattedKey!),
                Key = FormatKey(unformattedKey!)
            });
        });

        manageGroup.MapPost(options.VerifyAuthenticatorPostEndpoint, async Task<Results<BadRequest, Ok>> (TokenData token, UserManager<TUser> userManager, HttpContext request) =>
        {
            var user = await userManager.GetUserAsync(request.User);
            if (user is null)
            {
                return TypedResults.BadRequest();
            }

            // Strip spaces and hyphens
            var verificationCode = token.Token.Replace(" ", string.Empty).Replace("-", string.Empty);
            var is2faCodeValid = await userManager.VerifyTwoFactorTokenAsync(user, userManager.Options.Tokens.AuthenticatorTokenProvider, verificationCode);
            if (!is2faCodeValid)
            {
                return TypedResults.BadRequest();
            }

            await userManager.SetTwoFactorEnabledAsync(user, true);
            //_logger.LogInformation(LoggerEventIds.TwoFAEnabled, "User has enabled 2FA with an authenticator app.");

            return TypedResults.Ok();
        });

        return group;
    }

    private const string AuthenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";

    internal static string FormatKey(string unformattedKey)
    {
        var result = new StringBuilder();
        int currentPosition = 0;
        while (currentPosition + 4 < unformattedKey.Length)
        {
            result.Append(unformattedKey.AsSpan(currentPosition, 4)).Append(' ');
            currentPosition += 4;
        }
        if (currentPosition < unformattedKey.Length)
        {
            result.Append(unformattedKey.AsSpan(currentPosition));
        }

        return result.ToString().ToLowerInvariant();
    }

    private static string GenerateQrCodeUri(string userName, string unformattedKey)
    {
        return string.Format(
            CultureInfo.InvariantCulture,
            AuthenticatorUriFormat,
            AspNetCore.WebUtilities.WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes("Microsoft.AspNetCore.Identity.UI")),
            AspNetCore.WebUtilities.WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(userName)),
            unformattedKey);
    }
}
