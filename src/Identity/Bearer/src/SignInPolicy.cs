// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Microsoft.Extensions.Logging;

namespace Microsoft.AspNetCore.Identity;

internal class TokenSignInManager<TUser> where TUser : class
{
    private readonly UserManager<TUser> _userManager;
    private readonly ISignInPolicy<TUser> _signInPolicy;

    public TokenSignInManager(UserManager<TUser> userManager, ISignInPolicy<TUser> signInPolicy)
    {
        _userManager = userManager;
        _signInPolicy = signInPolicy;
    }

    public virtual async Task<(SignInResult, TUser?)> PasswordSignInAsync(string userName, string password)
    {
        var user = await _userManager.FindByNameAsync(userName);
        if (user is null)
        {
            return (SignInResult.Failed, null);
        }

        var result = await _signInPolicy.CanSignInAsync(user);
        if (result != null)
        {
            return (result, null);
        }

        if (await _userManager.CheckPasswordAsync(user, password))
        {
            return (SignInResult.Success, user);
        }

        return (SignInResult.Failed, null);
    }
}

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
}

