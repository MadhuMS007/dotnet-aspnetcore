// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Microsoft.Extensions.Logging;

namespace Microsoft.AspNetCore.Identity;

internal class SignInContext<TUser> where TUser : class
{
    public SignInContext(TUser user, UserManager<TUser> userManager)
    {
        User = user;
        UserManager = userManager;
    }

    public TUser User { get; }

    public UserManager<TUser> UserManager { get; }

    public string? SuppliedPassword { get; set; }

    public string? SuppliedTfaCode { get; set; }

    public SignInResult? Result { get; set; }

    public async Task<bool> IsTwoFactorEnabledAsync()
        => UserManager.SupportsUserTwoFactor &&
        await UserManager.GetTwoFactorEnabledAsync(User) &&
        (await UserManager.GetValidTwoFactorProvidersAsync(User)).Count > 0;

}

internal interface SignInStep<TUser> where TUser : class
{
    public Task ExecuteAsync(SignInContext<TUser> context);
}

internal class CheckConfirmationStep<TUser> : SignInStep<TUser> where TUser : class
{
    public async Task ExecuteAsync(SignInContext<TUser> context)
    {
        if (context.UserManager.Options.SignIn.RequireConfirmedEmail && !(await context.UserManager.IsEmailConfirmedAsync(context.User)))
        {
            //_logger.LogDebug(EventIds.UserCannotSignInWithoutConfirmedEmail, "User cannot sign in without a confirmed email.");
            context.Result = SignInResult.NotAllowed;
            return;
        }
        if (context.UserManager.Options.SignIn.RequireConfirmedPhoneNumber && !(await context.UserManager.IsPhoneNumberConfirmedAsync(context.User)))
        {
            //_logger.LogDebug(EventIds.UserCannotSignInWithoutConfirmedPhoneNumber, "User cannot sign in without a confirmed phone number.");
            context.Result = SignInResult.NotAllowed;
            return;
        }
        //if (context.UserManager.Options.SignIn.RequireConfirmedAccount && !(await _confirmation.IsConfirmedAsync(context.UserManager, user)))
        //{
        //    //_logger.LogDebug(EventIds.UserCannotSignInWithoutConfirmedAccount, "User cannot sign in without a confirmed account.");
        //    return SignInResult.NotAllowed;
        //}

        if (context.UserManager.SupportsUserLockout && await context.UserManager.IsLockedOutAsync(context.User))
        {
            //_logger.LogDebug(EventIds.UserLockedOut, "User is currently locked out.");
            context.Result = SignInResult.NotAllowed;
            return;
        }
    }
}

internal class CheckPasswordStep<TUser> : SignInStep<TUser> where TUser : class
{
    public async Task ExecuteAsync(SignInContext<TUser> context)
    {
        if (context.SuppliedPassword == null ||
            !await context.UserManager.CheckPasswordAsync(context.User, context.SuppliedPassword))
        {
            // TODO: also do lockout inc here
            context.Result = SignInResult.Failed;
        }
    }
}

internal class CheckTfaStep<TUser> : SignInStep<TUser> where TUser : class
{
    public async Task ExecuteAsync(SignInContext<TUser> context)
    {
        if (!await context.IsTwoFactorEnabledAsync())
        {
            return;
        }

        if (context.SuppliedTfaCode == null ||
            !await context.UserManager.VerifyTwoFactorTokenAsync(context.User, context.UserManager.Options.Tokens.AuthenticatorTokenProvider, context.SuppliedTfaCode))
        {
            // TODO: also do lockout inc here
            context.Result = SignInResult.Failed;
        }
    }
}

internal class TokenSignInManager<TUser> where TUser : class
{
    private readonly UserManager<TUser> _userManager;
    private readonly ISignInPolicy<TUser> _signInPolicy;

    public TokenSignInManager(UserManager<TUser> userManager, ISignInPolicy<TUser> signInPolicy)
    {
        _userManager = userManager;
        _signInPolicy = signInPolicy;
    }

    public virtual async Task<(SignInResult, TUser?)> PasswordSignInAsync(string userName, string password, string? tfaCode)
    {
        var user = await _userManager.FindByNameAsync(userName);
        if (user is null)
        {
            return (SignInResult.Failed, null);
        }

        var pipeline = new List<SignInStep<TUser>>()
        {
            new CheckConfirmationStep<TUser>(),
            new CheckPasswordStep<TUser>(),
            new CheckTfaStep<TUser>()
        };

        var context = new SignInContext<TUser>(user, _userManager)
        {
            SuppliedPassword = password,
            SuppliedTfaCode = tfaCode
        };
        foreach (var step in pipeline)
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

}

