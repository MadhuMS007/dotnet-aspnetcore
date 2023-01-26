// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Microsoft.Extensions.DependencyInjection;

internal class JsonTokenSerializer : ITokenSerializer
{
    public static JsonTokenSerializer Instance { get; private set; } = new JsonTokenSerializer();

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Trimming", "IL2026:Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code", Justification = "<Pending>")]
    public T? Deserialize<T>(string? serializedValue)
        => serializedValue != null ? JsonSerializer.Deserialize<T>(serializedValue) : default;

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Trimming", "IL2026:Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code", Justification = "<Pending>")]
    public string Serialize<T>(T value)
        => JsonSerializer.Serialize(value);
}

/// <summary>
/// Contains extension methods to <see cref="IdentityBuilder"/> for adding entity framework stores.
/// </summary>
public static class BearerBuilderExtensions
{
    /// <summary>
    /// Adds bearer token services.
    /// </summary>
    /// <typeparam name="TToken">The token type</typeparam>
    /// <returns>A <see cref="IdentityBearerTokenBuilder"/> instance.</returns>
    public static IdentityBearerTokenBuilder AddBearerTokens<TToken>(this IdentityBuilder builder)
        where TToken : class
    {
        // TODO: should add options validation that identity stores schema version is at least 2 (token version)
        builder.Services.TryAddSingleton<ITokenFormatManager, TokenFormatManager>();
        builder.Services.AddSingleton<IAccessTokenDenyPolicy, JtiBlocker>();
        builder.Services.AddSingleton<ITokenSerializer, JsonTokenSerializer>();
        var tokenManagerType = typeof(TokenManager<>).MakeGenericType(typeof(TToken));
        builder.Services.TryAddScoped(tokenManagerType);
        builder.Services.TryAddScoped(typeof(IUserTokenService<>).MakeGenericType(builder.UserType), typeof(UserTokenService<>).MakeGenericType(builder.UserType));
        builder.Services.TryAddScoped(typeof(IAccessTokenValidator), typeof(DefaultAccessTokenValidator<>).MakeGenericType(builder.UserType));

        return new IdentityBearerTokenBuilder(builder, typeof(TToken));
    }

    /// <summary>
    /// Adds an Entity Framework implementation of identity information stores.
    /// </summary>
    /// <typeparam name="TContext">The Entity Framework database context to use.</typeparam>
    /// <param name="builder">The <see cref="IdentityBuilder"/> instance this method extends.</param>
    /// <returns>The <see cref="IdentityBuilder"/> instance this method extends.</returns>
    public static IdentityBuilder AddTokenStore<TContext>(this IdentityBuilder builder)
        where TContext : DbContext
    {
        Type tokenType;
        Type tokenStoreType;
        var identityContext = FindGenericBaseType(typeof(TContext), typeof(IdentityDbContext<,,,,,,,,>));
        if (identityContext == null)
        {
            // If its a custom DbContext, we can only add the default POCOs
            tokenType = typeof(IdentityStoreToken);
            tokenStoreType = typeof(TokenStore<IdentityStoreToken, TContext>);
        }
        else
        {
            tokenType = identityContext.GenericTypeArguments[2];
            tokenStoreType = typeof(TokenStore<,>).MakeGenericType(tokenType, typeof(TContext));
        }

        builder.Services.TryAddScoped(typeof(ITokenStore<>).MakeGenericType(tokenType), tokenStoreType);
        return builder;
    }

    // REVIEW: copied from Identity.EF
    private static Type? FindGenericBaseType(Type currentType, Type genericBaseType)
    {
        Type? type = currentType;
        while (type != null)
        {
            var genericType = type.IsGenericType ? type.GetGenericTypeDefinition() : null;
            if (genericType != null && genericType == genericBaseType)
            {
                return type;
            }
            type = type.BaseType;
        }
        return null;
    }
}
