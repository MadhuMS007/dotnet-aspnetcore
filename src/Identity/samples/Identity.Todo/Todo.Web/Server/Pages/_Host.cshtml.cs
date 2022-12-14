// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Todo.Web.Server.Pages;

public class IndexModel : PageModel
{
    private readonly SocialProviders _socialProviders;

    public IndexModel(SocialProviders socialProviders)
    {
        _socialProviders = socialProviders;
    }

    public string[] ProviderNames { get; set; } = default!;
    public string? CurrentUserName { get; set; }

    public async Task OnGet()
    {
        ProviderNames = await _socialProviders.GetProviderNamesAsync();
        CurrentUserName = User.Identity!.Name;
    }
}
