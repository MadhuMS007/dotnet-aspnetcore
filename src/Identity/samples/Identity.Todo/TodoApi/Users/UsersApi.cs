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

            return TypedResults.Ok(new AuthToken(await tokenService.GetAccessTokenAsync(user), await tokenService.GetRefreshTokenAsync(user)));
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
                return TypedResults.Ok(new AuthToken(await tokenService.GetAccessTokenAsync(user), await tokenService.GetRefreshTokenAsync(user)));
            }

            return TypedResults.ValidationProblem(result.Errors.ToDictionary(e => e.Code, e => new[] { e.Description }));
        });

        group.MapPost("/refreshToken", async Task<Results<BadRequest, Ok<AuthToken>>> (RefreshToken tokenInfo, UserManager<TodoUser> userManager, TokenManager<TodoUser> tokenService) =>
        {
            if (tokenInfo.Token is null)
            {
                return TypedResults.BadRequest();
            }

            (var accessToken, var refreshToken) = await tokenService.RefreshTokensAsync(tokenInfo.Token);

            if (accessToken is null || refreshToken is null)
            {
                return TypedResults.BadRequest();
            }

            return TypedResults.Ok(new AuthToken(accessToken, refreshToken));
            //var isValid = await tokenService.ValidateRefreshToken(refreshTokenDTO.RefreshToken);

            //if (isValid)
            //{
            //    var user = await userManager.FindByIdAsync(refreshTokenDTO.Subject);

            //    if (user == null)
            //    {
            //        return Results.NotFound(new AuthResultDTO
            //        {
            //            Succeeded = false,
            //            StatusCode = 404,
            //            Message = "Could find the principal of the provided refresh token",
            //            TimeStamp = DateTime.Now,
            //        });
            //    }

            //    var tokens = await tokenService.GetTokensAsync(user);
            //    //Revoke the current refresh token by changing the expiry time and setting the isRevoked flag to true. 
            //    await tokenService.RevokeRefreshTokenAsync(user, refreshTokenDTO.RefreshToken);
            //    return Results.Ok(tokens);
            //}

            //return Results.UnprocessableEntity(new { Message = "Could not refresh the tokens" });
        });

        return group;
    }
}
