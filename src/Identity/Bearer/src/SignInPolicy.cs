// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Microsoft.Extensions.Logging;

namespace Microsoft.AspNetCore.Identity;

internal class SignInPolicy<TUser> : ISignInPolicy<TUser> where TUser : class
{
    private readonly UserManager<TUser> _userManager;
    private readonly ILogger<SignInPolicy<TUser>> _logger;
    private readonly IUserConfirmation<TUser> _confirmation;

    public SignInPolicy(UserManager<TUser> userManager, ILogger<SignInPolicy<TUser>> logger,
        IUserConfirmation<TUser> confirmation)
    {
        _userManager = userManager;
        _logger = logger;
        _confirmation = confirmation;
    }

    /// <inheritdoc/>
    public virtual async Task<SignInResult?> CanSignInAsync(TUser user)
    {
        if (_userManager.Options.SignIn.RequireConfirmedEmail && !(await _userManager.IsEmailConfirmedAsync(user)))
        {
            //_logger.LogDebug(EventIds.UserCannotSignInWithoutConfirmedEmail, "User cannot sign in without a confirmed email.");
            return SignInResult.NotAllowed;
        }
        if (_userManager.Options.SignIn.RequireConfirmedPhoneNumber && !(await _userManager.IsPhoneNumberConfirmedAsync(user)))
        {
            //_logger.LogDebug(EventIds.UserCannotSignInWithoutConfirmedPhoneNumber, "User cannot sign in without a confirmed phone number.");
            return SignInResult.NotAllowed;
        }
        if (_userManager.Options.SignIn.RequireConfirmedAccount && !(await _confirmation.IsConfirmedAsync(_userManager, user)))
        {
            //_logger.LogDebug(EventIds.UserCannotSignInWithoutConfirmedAccount, "User cannot sign in without a confirmed account.");
            return SignInResult.NotAllowed;
        }

        if (_userManager.SupportsUserLockout && await _userManager.IsLockedOutAsync(user))
        {
            //_logger.LogDebug(EventIds.UserLockedOut, "User is currently locked out.");
            return SignInResult.LockedOut;
        }

        return null;
    }

    /// <inheritdoc/>
    public virtual async Task<bool> IsTwoFactorEnabledAsync(TUser user)
        => _userManager.SupportsUserTwoFactor &&
        await _userManager.GetTwoFactorEnabledAsync(user) &&
        (await _userManager.GetValidTwoFactorProvidersAsync(user)).Count > 0;

    /// <inheritdoc/>
    public virtual async Task<(SignInResult, TUser?)> PasswordSignInAsync(string userName, string password, string? tfaCode)
    {
        var user = await _userManager.FindByNameAsync(userName);
        if (user is null)
        {
            return (SignInResult.Failed, null);
        }

        var context = new SignInContext<TUser>(user, _userManager, this)
        {
            SuppliedPassword = password,
            SuppliedTfaCode = tfaCode
        };
        // TODO: check the pipeline is legit/valid?
        foreach (var step in _userManager.Options.SignIn.PasswordSignInSteps)
        {
            await step.ExecuteAsync(context);
            if (context.Result != null)
            {
                // Only return the user if successful
                return (context.Result,
                    context.Result.Succeeded ? user : null);
            }
        }

        // If we finished the pipeline without issue, this is a successful sign in.
        return (SignInResult.Success, user);
    }
}
