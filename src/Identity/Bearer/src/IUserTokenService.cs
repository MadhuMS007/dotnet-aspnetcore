// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;

namespace Microsoft.AspNetCore.Identity;

/// <summary>
/// Token service for access and refresh tokens
/// </summary>
/// <typeparam name="TUser"></typeparam>
public interface IUserTokenService<TUser> where TUser : class
{
    /// <summary>
    /// Get a bearer token for the user.
    /// </summary>
    /// <param name="user">The user.</param>
    /// <returns></returns>
    Task<string> GetAccessTokenAsync(TUser user);

    /// <summary>
    /// Attempt to read access token.
    /// </summary>
    /// <param name="accessToken">The access token.</param>
    /// <returns>A TokenInfo for the accessToken, or null if the access token is invalid or unable to be read.</returns>
    Task<TokenInfo?> ReadAccessTokenAsync(string accessToken);

    /// <summary>
    /// Get a refresh token for the user.
    /// </summary>
    /// <param name="user">The user.</param>
    /// <returns></returns>
    Task<string> GetRefreshTokenAsync(TUser user);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="user">The user.</param>
    /// <param name="token">The refresh token.</param>
    /// <returns></returns>
    Task<IdentityResult> RevokeRefreshAsync(TUser user, string token);

    /// <summary>
    /// Returns a new access and refresh token if refreshToken is valid, will also
    /// consume the refreshToken via calling Revoke on it.
    /// </summary>
    /// <param name="refreshToken"></param>
    /// <returns>(access token, refresh token) if successful, (null, null) otherwise.</returns>
    Task<(string?, string?)> RefreshTokensAsync(string refreshToken);
}

// Scoped way to find or generate a session id for the current user/request
internal interface IUserSessionTracker
{
    // This should return an existing session id if user is authenticated
    // If request is not authenticated, this should create a new id
    Task<string> GetSessionId();
}

internal class UserTokenService<TUser> : IUserTokenService<TUser> where TUser : class
{
    private readonly TokenManager<IdentityStoreToken> _tokenManager;
    private readonly ISystemClock _clock;
    private readonly ITokenFormatManager _formatManager;

    public UserTokenService(TokenManager<IdentityStoreToken> tokenManager, ISystemClock clock, UserManager<TUser> userManager, ITokenFormatManager formatManager)
    {
        _tokenManager = tokenManager;
        _clock = clock;
        UserManager = userManager;
        _formatManager = formatManager;
    }

    /// <summary>
    /// The <see cref="UserManager{TUser}"/> used.
    /// </summary>
    public UserManager<TUser> UserManager { get; set; }

    private async Task BuildPayloadAsync(TUser user, IDictionary<string, string> payload)
    {
        // Based on UserClaimsPrincipalFactory
        //var userId = await UserManager.GetUserIdAsync(user).ConfigureAwait(false);
        var userName = await UserManager.GetUserNameAsync(user).ConfigureAwait(false);
        payload[ClaimTypes.NameIdentifier] = userName!;

        if (UserManager.SupportsUserEmail)
        {
            var email = await UserManager.GetEmailAsync(user).ConfigureAwait(false);
            if (!string.IsNullOrEmpty(email))
            {
                payload["email"] = email;
            }
        }
        if (UserManager.SupportsUserSecurityStamp)
        {
            payload[UserManager.Options.ClaimsIdentity.SecurityStampClaimType] =
                await UserManager.GetSecurityStampAsync(user).ConfigureAwait(false);
        }
        if (UserManager.SupportsUserClaim)
        {
            var claims = await UserManager.GetClaimsAsync(user).ConfigureAwait(false);
            foreach (var claim in claims)
            {
                payload[claim.Type] = claim.Value;
            }
        }

        // REVIEW: why more than one aud?
        //payload["aud"] = _bearerOptions.Audiences.LastOrDefault()!;
    }

    /// <inheritdoc/>
    public virtual async Task<string> GetAccessTokenAsync(TUser user)
    {
        // TODO: Device/SessionId needs should be passed in or set on TokenManager?

        // REVIEW: we could throw instead?
        if (user == null)
        {
            return string.Empty;
        }

        var payload = new Dictionary<string, string>();
        await BuildPayloadAsync(user, payload);
        var userId = await UserManager.GetUserIdAsync(user).ConfigureAwait(false);

        (var format, var provider) = _formatManager.GetFormatProvider(TokenPurpose.AccessToken);

        // Store the token metadata, with jwt token as payload
        var info = new TokenInfo(Guid.NewGuid().ToString(),
            format, userId, TokenPurpose.AccessToken, TokenStatus.Active)
        {
            Expiration = DateTimeOffset.UtcNow.AddDays(1),
            Payload = payload
        };

        if (_tokenManager.Options.StoreAccessTokens)
        {
            await _tokenManager.StoreAsync(info).ConfigureAwait(false);
        }

        return await provider.CreateTokenAsync(info);
    }

    /// <inheritdoc/>
    public virtual async Task<string> GetRefreshTokenAsync(TUser user)
    {
        (var format, var provider) = _formatManager.GetFormatProvider(TokenPurpose.RefreshToken);

        // Build the raw token and payload
        var userId = await UserManager.GetUserIdAsync(user);

        // Store the token metadata, refresh tokens don't need additional data
        // so no payload is specified for the token info.
        var info = new TokenInfo(Guid.NewGuid().ToString(),
            format, userId, TokenPurpose.RefreshToken, TokenStatus.Active)
        {
            Expiration = DateTimeOffset.UtcNow.AddDays(1)
        };
        var token = await _tokenManager.Store.NewAsync(info, _tokenManager.CancellationToken).ConfigureAwait(false);
        await _tokenManager.Store.CreateAsync(token, _tokenManager.CancellationToken);
        return await provider.CreateTokenAsync(info);
    }

    /// <summary>
    /// Check if the token status is valid. Defaults to only active token status.
    /// </summary>
    /// <param name="status">The token status.</param>
    /// <returns>true if the token is should be allowed.</returns>
    protected virtual bool CheckTokenStatus(string status)
        => status == TokenStatus.Active;

    /// <inheritdoc/>
    public virtual async Task<(string?, string?)> RefreshTokensAsync(string refreshToken)
    {
        // TODO: tests to write:
        // with deleted user
        (var _, var provider) = _formatManager.GetFormatProvider(TokenPurpose.RefreshToken);

        var tokenInfo = await provider.ReadTokenAsync(refreshToken, TokenPurpose.RefreshToken);
        if (tokenInfo == null)
        {
            return (null, null);
        }

        var tok = await _tokenManager.Store.FindByIdAsync(tokenInfo.Id, _tokenManager.CancellationToken).ConfigureAwait(false);
        if (tok == null)
        {
            return (null, null);
        }

        var status = await _tokenManager.Store.GetStatusAsync(tok, _tokenManager.CancellationToken).ConfigureAwait(false);
        if (!CheckTokenStatus(status))
        {
            return (null, null);
        }

        var expires = await _tokenManager.Store.GetExpirationAsync(tok, _tokenManager.CancellationToken).ConfigureAwait(false);
        if (expires < _clock.UtcNow)
        {
            return (null, null);
        }

        var userId = await _tokenManager.Store.GetSubjectAsync(tok, _tokenManager.CancellationToken).ConfigureAwait(false);
        var user = await UserManager.FindByIdAsync(userId).ConfigureAwait(false);
        if (user != null)
        {
            // Mark the refresh token as used
            await _tokenManager.Store.SetStatusAsync(tok, TokenStatus.Inactive, _tokenManager.CancellationToken).ConfigureAwait(false);
            await _tokenManager.Store.UpdateAsync(tok, _tokenManager.CancellationToken).ConfigureAwait(false);
            return (await GetAccessTokenAsync(user), await GetRefreshTokenAsync(user));
        }
        return (null, null);
    }

    public virtual async Task<IdentityResult> RevokeRefreshAsync(TUser user, string token)
    {
        (var _, var provider) = _formatManager.GetFormatProvider(TokenPurpose.RefreshToken);

        var tokenInfo = await provider.ReadTokenAsync(token, TokenPurpose.RefreshToken);
        if (tokenInfo == null)
        {
            return IdentityResult.Success;
        }

        var tok = await _tokenManager.Store.FindByIdAsync(tokenInfo.Id, _tokenManager.CancellationToken).ConfigureAwait(false);
        if (tok != null)
        {
            await _tokenManager.Store.SetStatusAsync(tok, TokenStatus.Revoked, _tokenManager.CancellationToken);
            return await _tokenManager.Store.UpdateAsync(tok, _tokenManager.CancellationToken).ConfigureAwait(false); ;
        }
        return IdentityResult.Success;
    }

    /// <inheritdoc/>
    public virtual async Task<TokenInfo?> ReadAccessTokenAsync(string accessToken)
    {
        (var _, var provider) = _formatManager.GetFormatProvider(TokenPurpose.AccessToken);
        return await provider.ReadTokenAsync(accessToken, TokenPurpose.AccessToken).ConfigureAwait(false);
    }
}

/// <summary>
/// Responsible for mapping token formats to <see cref="ITokenFormatProvider"/>.
/// </summary>
internal interface ITokenFormatManager
{
    /// <summary>
    /// Associate a format with a provider.
    /// </summary>
    /// <param name="format">The token format.</param>
    /// <param name="provider">The provider.</param>
    /// <returns></returns>
    void SetProvider(string format, ITokenFormatProvider provider);

    /// <summary>
    /// Return the <see cref="ITokenFormatProvider"/> for the specified format.
    /// </summary>
    /// <param name="format">The token format.</param>
    /// <returns>The <see cref="ITokenFormatProvider"/> for the format.</returns>
    ITokenFormatProvider? GetProvider(string format);

    /// <summary>
    /// Get the format and provider for a token purpose.
    /// </summary>
    /// <param name="tokenPurpose">The token purpose.</param>
    /// <returns>The token format and provider for the purpose.</returns>
    (string, ITokenFormatProvider) GetFormatProvider(string tokenPurpose);
}

// Maybe just merge into UserTokenService??
internal class TokenFormatManager : ITokenFormatManager
{
    public TokenFormatManager(IOptions<TokenManagerOptions> options, IDataProtectionProvider dp)
    {
        Options = options.Value;

        // TODO: This should move to options config
        Options.FormatProviderMap[TokenFormat.JWT] = new DefaultTokenFormat(dp);
        Options.FormatProviderMap[TokenFormat.Code] = new TokenIdFormat();

        Options.PurposeFormatMap[TokenPurpose.RefreshToken] = TokenFormat.Code;
        Options.PurposeFormatMap[TokenPurpose.AccessToken] = TokenFormat.JWT;
    }

    public ITokenFormatProvider? GetProvider(string format)
        => Options.FormatProviderMap.TryGetValue(format, out var value) ? value : null;

    public void SetProvider(string format, ITokenFormatProvider provider)
        => Options.FormatProviderMap[format] = provider;

    public (string, ITokenFormatProvider) GetFormatProvider(string tokenPurpose)
    {
        // TODO: someone should be validating these
        var format = Options.PurposeFormatMap[tokenPurpose];
        if (!Options.FormatProviderMap.TryGetValue(format, out var provider))
        {
            throw new InvalidOperationException($"Could not find token format provider {format} registered for purpose: {tokenPurpose}.");
        }
        return (format, provider);
    }

    /// <summary>
    /// The <see cref="TokenManagerOptions"/>.
    /// </summary>
    public TokenManagerOptions Options { get; set; }
}

