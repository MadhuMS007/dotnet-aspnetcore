// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Identity;

/// <summary>
/// Options for configuring sign in.
/// </summary>
public class SignInOptions
{
    /// <summary>
    /// Gets or sets a flag indicating whether a confirmed email address is required to sign in. Defaults to false.
    /// </summary>
    /// <value>True if a user must have a confirmed email address before they can sign in, otherwise false.</value>
    public bool RequireConfirmedEmail { get; set; }

    /// <summary>
    /// Gets or sets a flag indicating whether a confirmed telephone number is required to sign in. Defaults to false.
    /// </summary>
    /// <value>True if a user must have a confirmed telephone number before they can sign in, otherwise false.</value>
    public bool RequireConfirmedPhoneNumber { get; set; }

    /// <summary>
    /// Gets or sets a flag indicating whether a confirmed <see cref="IUserConfirmation{TUser}"/> account is required to sign in. Defaults to false.
    /// </summary>
    /// <value>True if a user must have a confirmed account before they can sign in, otherwise false.</value>
    public bool RequireConfirmedAccount { get; set; }

    internal IList<ISignInStep> PasswordSignInSteps { get; set; } = new List<ISignInStep>()
    {
        new CheckConfirmationStep(),
        new CheckPasswordStep(),
        new CheckTfaStep()
    };
}

internal class SignInContext<TUser> where TUser : class
{
    public SignInContext(TUser user, UserManager<TUser> userManager, ISignInPolicy<TUser> signInPolicy)
    {
        User = user;
        UserManager = userManager;
        SignInPolicy = signInPolicy;
    }

    public ISignInPolicy<TUser> SignInPolicy { get; }

    public TUser User { get; }

    public UserManager<TUser> UserManager { get; }

    public string? SuppliedPassword { get; set; }

    public string? SuppliedTfaCode { get; set; }

    public SignInResult? Result { get; set; }


    public async Task<bool> IsTwoFactorEnabledAsync()
        => UserManager.SupportsUserTwoFactor &&
        await UserManager.GetTwoFactorEnabledAsync(User).ConfigureAwait(false) &&
        (await UserManager.GetValidTwoFactorProvidersAsync(User).ConfigureAwait(false)).Count > 0;
}

internal interface ISignInStep
{
    public Task ExecuteAsync<TUser>(SignInContext<TUser> context) where TUser : class;
}

internal class CheckConfirmationStep : ISignInStep
{
    public async Task ExecuteAsync<TUser>(SignInContext<TUser> context) where TUser : class
        => context.Result = await context.SignInPolicy.CanSignInAsync(context.User).ConfigureAwait(false);
}

internal class CheckPasswordStep : ISignInStep
{
    public async Task ExecuteAsync<TUser>(SignInContext<TUser> context) where TUser : class
    {
        if (context.SuppliedPassword == null ||
            !await context.UserManager.CheckPasswordAsync(context.User, context.SuppliedPassword).ConfigureAwait(false))
        {
            // TODO: also do lockout inc here
            context.Result = SignInResult.Failed;
        }
    }
}

internal class CheckTfaStep : ISignInStep
{
    public async Task ExecuteAsync<TUser>(SignInContext<TUser> context) where TUser : class
    {
        if (!await context.SignInPolicy.IsTwoFactorEnabledAsync(context.User).ConfigureAwait(false))
        {
            return;
        }

        if (context.SuppliedTfaCode == null ||
            !await context.UserManager.VerifyTwoFactorTokenAsync(context.User, context.UserManager.Options.Tokens.AuthenticatorTokenProvider, context.SuppliedTfaCode).ConfigureAwait(false))
        {
            // TODO: also do lockout inc here
            context.Result = SignInResult.Failed;
        }
    }
}

