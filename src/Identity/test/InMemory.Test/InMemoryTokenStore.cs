// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Microsoft.AspNetCore.Identity.Test;
using Microsoft.Extensions.DependencyInjection;

namespace Microsoft.AspNetCore.Identity.InMemory;

public class InMemoryTokenStore<TUser, TRole> :
    InMemoryStore<TUser, TRole>,
    ITokenStore<IdentityStoreToken>,
    IKeyStore
    where TRole : PocoRole
    where TUser : PocoUser
{
    public readonly IDictionary<string, IdentityStoreToken> _tokens = new Dictionary<string, IdentityStoreToken>();
    public readonly IDictionary<string, KeyInfo> _keys = new Dictionary<string, KeyInfo>();
    public readonly ITokenSerializer _serializer = new JsonTokenSerizlier();

    public Task<IdentityResult> AddAsync(string keyId, string providerId, string format, string data, CancellationToken cancellationToken)
    {
        _keys[keyId] = new KeyInfo()
        {
            Id = keyId,
            ProviderId = providerId,
            Format = format,
            Data = data,
            Created = DateTimeOffset.UtcNow
        };
        return Task.FromResult(IdentityResult.Success);
    }

    public Task<IdentityResult> CreateAsync(IdentityStoreToken token, CancellationToken cancellationToken)
    {
        _tokens[token.Id] = token;
        return Task.FromResult(IdentityResult.Success);
    }

    public Task<IdentityResult> DeleteAsync(IdentityStoreToken token, CancellationToken cancellationToken)
    {
        _tokens.Remove(token.Id);
        return Task.FromResult(IdentityResult.Success);
    }

    Task<IdentityStoreToken> ITokenStore<IdentityStoreToken>.FindByIdAsync(string tokenId, CancellationToken cancellationToken)
    {
        return Task.FromResult(_tokens.Values.Where(t => t.Id == tokenId).SingleOrDefault());
    }

    public Task<IdentityStoreToken> FindAsync(string purpose, string value, CancellationToken cancellationToken)
        => Task.FromResult(_tokens.Values.Where(t => t.Purpose == purpose && t.Payload == value).SingleOrDefault());

    public Task<DateTimeOffset> GetExpirationAsync(IdentityStoreToken token, CancellationToken cancellationToken)
        => Task.FromResult(token.Expiration);

    public Task<string> GetStatusAsync(IdentityStoreToken token, CancellationToken cancellationToken)
        => Task.FromResult(token.Status);

    public Task<string> GetSubjectAsync(IdentityStoreToken token, CancellationToken cancellationToken)
        => Task.FromResult(token.Subject);

    public Task<IdentityStoreToken> NewAsync(TokenInfo tokenInfo, CancellationToken cancellationToken)
    {
        return Task.FromResult(new IdentityStoreToken(tokenInfo)
        {
            Payload = _serializer.Serialize(tokenInfo.Payload)
        });
        ;
    }

    public Task<IdentityResult> RemoveAsync(string keyId, CancellationToken cancellationToken)
    {
        _keys.Remove(keyId);
        return Task.FromResult(IdentityResult.Success);
    }

    public Task SetExpirationAsync(IdentityStoreToken token, DateTimeOffset expiration, CancellationToken cancellationToken)
    {
        token.Expiration = expiration;
        return Task.CompletedTask;
    }

    public Task SetStatusAsync(IdentityStoreToken token, string status, CancellationToken cancellationToken)
    {
        token.Status = status;
        return Task.CompletedTask;
    }

    public Task SetSubjectAsync(IdentityStoreToken token, string subject, CancellationToken cancellationToken)
    {
        token.Subject = subject;
        return Task.CompletedTask;
    }

    public Task<IdentityResult> UpdateAsync(IdentityStoreToken token, CancellationToken cancellationToken)
    {
        _tokens[token.Id] = token;
        return Task.FromResult(IdentityResult.Success);
    }

    Task<KeyInfo> IKeyStore.FindByIdAsync(string keyId, CancellationToken cancellationToken)
    {
        _keys.TryGetValue(keyId, out var result);
        return Task.FromResult(result);
    }

    public Task<TokenInfo> GetTokenInfoAsync<TPayload>(IdentityStoreToken token, CancellationToken cancellationToken)
    {
        var info = new TokenInfo(token.Id, token.Format, token.Subject, token.Purpose, token.Status);
        info.Payload = _serializer.Deserialize<TPayload>(token.Payload);
        return Task.FromResult(info);
    }

    public Task<string> GetFormatAsync(IdentityStoreToken token, CancellationToken cancellationToken)
        => Task.FromResult(token.Format);

    public Task SetFormatAsync(IdentityStoreToken token, string format, CancellationToken cancellationToken)
    {
        token.Format = format;
        return Task.CompletedTask;
    }
}
