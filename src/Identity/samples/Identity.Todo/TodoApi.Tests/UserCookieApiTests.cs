// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Globalization;
using System.Net.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Bearer;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;

namespace TodoApi.Tests;

public class UserCookieApiTests
{
    public const string IdentityEndpoint = $"/identity/cookies";
    public const string RegisterEndpoint = $"{IdentityEndpoint}/register";
    public const string ConfirmEmailEndpoint = $"{IdentityEndpoint}/confirmEmail";
    public const string LoginEndpoint = $"{IdentityEndpoint}/login";
    public const string RefreshEndpoint = $"{IdentityEndpoint}/refresh";
    public const string IdentityManageEndpoint = $"{IdentityEndpoint}/manage";
    public const string LogoutEndpoint = $"{IdentityManageEndpoint}/logout";
    public const string VerifyAuthenticatorEndpoint = $"{IdentityManageEndpoint}/verifyAuthenticator";
    public const string GetAuthenticatorEndpoint = $"{IdentityManageEndpoint}/authenticator";

    [Fact]
    public async Task CanCreateAUser()
    {
        await using var application = new TodoApplication();
        await using var db = application.CreateTodoDbContext();

        var client = application.CreateClient();
        var response = await client.PostAsJsonAsync(RegisterEndpoint, new UserInfo { Username = "todouser", Password = "@pwd" });

        Assert.True(response.IsSuccessStatusCode);

        var user = db.Users.Single();
        Assert.NotNull(user);

        Assert.Equal("todouser", user.UserName);
    }

    [Fact]
    public async Task MissingUserOrPasswordReturnsBadRequest()
    {
        await using var application = new TodoApplication();
        await using var db = application.CreateTodoDbContext();

        var client = application.CreateClient();
        var response = await client.PostAsJsonAsync(RegisterEndpoint, new UserInfo { Username = "todouser", Password = "" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        var problemDetails = await response.Content.ReadFromJsonAsync<ValidationProblemDetails>();
        Assert.NotNull(problemDetails);

        Assert.Equal("One or more validation errors occurred.", problemDetails.Title);
        Assert.NotEmpty(problemDetails.Errors);

        Assert.Equal(new[] { "Passwords must be at least 1 characters." }, problemDetails.Errors["PasswordTooShort"]);
        // TODO: fix validation
//        Assert.Equal(new[] { "The Password field is required." }, problemDetails.Errors["Password"]);

        response = await client.PostAsJsonAsync(RegisterEndpoint, new UserInfo { Username = "", Password = "password" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        problemDetails = await response.Content.ReadFromJsonAsync<ValidationProblemDetails>();
        Assert.NotNull(problemDetails);

        Assert.Equal("One or more validation errors occurred.", problemDetails.Title);
        Assert.NotEmpty(problemDetails.Errors);
        Assert.Equal(new[] { "Username '' is invalid, can only contain letters or digits." }, problemDetails.Errors["InvalidUserName"]);
        // TODO: fix validation
        //Assert.Equal(new[] { "The Username field is required." }, problemDetails.Errors["Username"]);
    }

    // TODO: Validation was removed
    //[Fact]
    //public async Task MissingUsernameOrProviderKeyReturnsBadRequest()
    //{
    //    await using var application = new TodoApplication();
    //    await using var db = application.CreateTodoDbContext();

    //    var client = application.CreateClient();
    //    var response = await client.PostAsJsonAsync("/users/token/Google", new ExternalUserInfo { Username = "todouser" });

    //    Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

    //    var problemDetails = await response.Content.ReadFromJsonAsync<ValidationProblemDetails>();
    //    Assert.NotNull(problemDetails);

    //    Assert.Equal("One or more validation errors occurred.", problemDetails.Title);
    //    Assert.NotEmpty(problemDetails.Errors);
    //    Assert.Equal(new[] { $"The {nameof(ExternalUserInfo.ProviderKey)} field is required." }, problemDetails.Errors[nameof(ExternalUserInfo.ProviderKey)]);

    //    response = await client.PostAsJsonAsync("/users/token/Google", new ExternalUserInfo { ProviderKey = "somekey" });

    //    Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

    //    problemDetails = await response.Content.ReadFromJsonAsync<ValidationProblemDetails>();
    //    Assert.NotNull(problemDetails);

    //    Assert.Equal("One or more validation errors occurred.", problemDetails.Title);
    //    Assert.NotEmpty(problemDetails.Errors);
    //    Assert.Equal(new[] { $"The Username field is required." }, problemDetails.Errors["Username"]);
    //}

    [Fact]
    public async Task CanGetCookieForValidUser()
    {
        await using var application = new TodoApplication();
        await using var db = application.CreateTodoDbContext();
        await application.CreateUserAsync("todouser", "p@assw0rd1");

        var client = application.CreateClient();
        var response = await client.PostAsJsonAsync(LoginEndpoint, new UserInfo { Username = "todouser", Password = "p@assw0rd1" });
        await VerifyCookie(client, response);
    }

    [Fact]
    public async Task CanCustomizeLoginEndpoint()
    {
        await using var application = new TodoApplication(o =>
        {
            o.Endpoints.IdentityRouteGroup = "/wee";
            o.Endpoints.IdentityCookieRouteGroup = "/cake";
            o.Endpoints.LoginEndpoint = "/yolo";
        });
        await using var db = application.CreateTodoDbContext();
        await application.CreateUserAsync("todouser", "p@assw0rd1");

        var client = application.CreateClient();
        var response = await client.PostAsJsonAsync("/wee/cake/yolo", new UserInfo { Username = "todouser", Password = "p@assw0rd1" });
        await VerifyCookie(client, response);
    }

    private class AlwaysLockedOutStep : ISignInStep
    {
        public Task ExecuteAsync<TUser>(SignInContext<TUser> context) where TUser : class
        {
            context.Result = Microsoft.AspNetCore.Identity.SignInResult.LockedOut;
            return Task.CompletedTask;
        }
    }

    [Fact]
    public async Task CanCustomizePasswordSignIn()
    {
        await using var application = new TodoApplication(o =>
        {
            o.SignIn.PasswordSignInSteps.Add(new AlwaysLockedOutStep());
        });
        await using var db = application.CreateTodoDbContext();
        await application.CreateUserAsync("todouser", "p@assw0rd1");

        var client = application.CreateClient();
        var response = await client.PostAsJsonAsync(LoginEndpoint, new UserInfo { Username = "todouser", Password = "p@assw0rd1" });

        // Fails because we now always return locked out.
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    private async Task<string> VerifyCookie(HttpClient client, HttpResponseMessage response)
    {
        Assert.True(response.IsSuccessStatusCode);

        string? setCookie = null;
        if (response.Headers.Contains("Set-Cookie"))
        {
            setCookie = response.Headers.GetValues("Set-Cookie").SingleOrDefault();
        }

        Assert.NotNull(setCookie);

        // Check that the token is indeed valid
        var req = new HttpRequestMessage(HttpMethod.Get, "/todos");
        req.Headers.Add("Cookie", setCookie);
        response = await client.SendAsync(req);

        Assert.True(response.IsSuccessStatusCode);

        return setCookie;
    }

    [Fact]
    public async Task CanRequireConfirmedUsers()
    {
        await using var application = new TodoApplication();
        application.RequireConfirmedUserEmails();
        await using var db = application.CreateTodoDbContext();
        (var user, var code) = await application.CreateUserAsync("todouser", "p@assw0rd1", generateCode: true);

        Assert.NotNull(code);

        var client = application.CreateClient();
        var response = await client.PostAsJsonAsync(LoginEndpoint, new UserInfo { Username = "todouser", Password = "p@assw0rd1" });

        // Bad request for unconfirmed users
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        // Confirm the user
        response = await client.PostAsJsonAsync(ConfirmEmailEndpoint, new VerificationToken { UserId = user.Id, Token = code });
        Assert.True(response.IsSuccessStatusCode);

        await VerifyCookie(client, await client.PostAsJsonAsync(LoginEndpoint, new UserInfo { Username = "todouser", Password = "p@assw0rd1" }));
    }

    internal static string CalculateCode(string key)
    {
        // Based on AuthenticatorTokenProvider
        var keyBytes = Base32.FromBase32(key);
        var unixTimestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var timestep = Convert.ToInt64(unixTimestamp / 30);
        return Rfc6238AuthenticationService.ComputeTotp(keyBytes, (ulong)timestep, modifierBytes: null).ToString(CultureInfo.InvariantCulture);
    }

    [Fact]
    public async Task CanAddAuthenticator()
    {
        await using var application = new TodoApplication();
        await using var db = application.CreateTodoDbContext();
        (var user, _) = await application.CreateUserAsync("todouser", "p@assw0rd1");

        var client = await application.CreateClientAsync(user.Id);
        var authenticator = await client.GetFromJsonAsync<AuthenticatorInfo>(GetAuthenticatorEndpoint);
        Assert.NotNull(authenticator);
        Assert.NotNull(authenticator.Key);
        Assert.NotNull(authenticator.Uri);

        var key = await application.GetAuthenticatorCode(user);
        Assert.NotNull(key);
        Assert.Equal(authenticator.Key, BearerApi.FormatKey(key));
        var authenticatorCode = CalculateCode(key);

        var response = await client.PostAsJsonAsync(VerifyAuthenticatorEndpoint, new TokenData() { Token = authenticatorCode });
        Assert.True(response.IsSuccessStatusCode);

        // Verify that login will now fail since tfa is required
        var newClient = application.CreateClient();
        response = await newClient.PostAsJsonAsync(LoginEndpoint, new PasswordLoginInfo { Username = "todouser", Password = "p@assw0rd1" });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        // Verify that login works with code
        response = await newClient.PostAsJsonAsync(LoginEndpoint, new PasswordLoginInfo { Username = "todouser", Password = "p@assw0rd1", TfaCode = CalculateCode(key) });
        await VerifyCookie(client, response);
    }

    [Fact]
    public async Task CanLogout()
    {
        await using var application = new TodoApplication();
        await using var db = application.CreateTodoDbContext();
        await application.CreateUserAsync("todouser", "p@assw0rd1");

        var client = application.CreateClient();
        var response = await client.PostAsJsonAsync(LoginEndpoint, new UserInfo { Username = "todouser", Password = "p@assw0rd1" });

        // Check that the token is indeed valid
        var cookie = await VerifyCookie(client, response);

        // Logout
        var req = new HttpRequestMessage(HttpMethod.Post, LogoutEndpoint);
        req.Headers.Add("Set-Cookie", cookie);
        response = await client.SendAsync(req);
        Assert.True(response.IsSuccessStatusCode);

        // TODO: verify that logout clears cookie
    }

    [Fact]
    public async Task BadRequestForInvalidCredentials()
    {
        await using var application = new TodoApplication();
        await using var db = application.CreateTodoDbContext();
        await application.CreateUserAsync("todouser", "p@assw0rd1");

        var client = application.CreateClient();
        var response = await client.PostAsJsonAsync(LoginEndpoint, new UserInfo { Username = "todouser", Password = "prd1" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }
}
