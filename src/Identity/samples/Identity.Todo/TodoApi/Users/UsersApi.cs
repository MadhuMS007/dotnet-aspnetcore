// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;

namespace TodoApi;

public static class UsersApi
{
    public static RouteGroupBuilder MapUsers(this IEndpointRouteBuilder routes)
    {
        var group = routes.MapGroup("/users");

        group.WithTags("Users");

        //group.WithParameterValidation(typeof(UserInfo), typeof(ExternalUserInfo));

        group.MapPost("/", async Task<Results<Ok, ValidationProblem>> (UserInfo newUser, UserManager<TodoUser> userManager) =>
        {
            var result = await userManager.CreateAsync(new() { UserName = newUser.Username }, newUser.Password);

            if (result.Succeeded)
            {
                return TypedResults.Ok();
            }

            return TypedResults.ValidationProblem(result.Errors.ToDictionary(e => e.Code, e => new[] { e.Description }));
        });

        group.MapPost("/token", async Task<Results<BadRequest, Ok<AuthToken>>> (UserInfo userInfo, UserManager<TodoUser> userManager, TokenManager<TodoUser> tokenService) =>
        {
            var user = await userManager.FindByNameAsync(userInfo.Username);

            if (user is null || !await userManager.CheckPasswordAsync(user, userInfo.Password))
            {
                return TypedResults.BadRequest();
            }

            return TypedResults.Ok(new AuthToken(await tokenService.GetBearerAsync(user)));
        });

        group.MapPost("/token/{provider}", async Task<Results<Ok<AuthToken>, ValidationProblem>> (string provider, ExternalUserInfo userInfo, UserManager<TodoUser> userManager, TokenManager<TodoUser> tokenService) =>
        {
            var user = await userManager.FindByLoginAsync(provider, userInfo.ProviderKey);

            var result = IdentityResult.Success;

            if (user is null)
            {
                user = new TodoUser() { UserName = userInfo.Username };

                result = await userManager.CreateAsync(user);

                if (result.Succeeded)
                {
                    result = await userManager.AddLoginAsync(user, new UserLoginInfo(provider, userInfo.ProviderKey, displayName: null));
                }
            }

            if (result.Succeeded)
            {
                return TypedResults.Ok(new AuthToken(await tokenService.GetBearerAsync(user)));
            }

            return TypedResults.ValidationProblem(result.Errors.ToDictionary(e => e.Code, e => new[] { e.Description }));
        });

        return group;
    }
}
