// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Microsoft.AspNetCore.Identity.Test;
using Newtonsoft.Json.Linq;

namespace Microsoft.AspNetCore.Identity.InMemory;

public class InMemoryTokenStore<TUser, TRole> :
    InMemoryStore<TUser, TRole>,
    ITokenStore<IdentityToken>,
    IKeyStore
    where TRole : PocoRole
    where TUser : PocoUser
{
    private readonly IDictionary<string, IdentityToken> _tokens = new Dictionary<string, IdentityToken>();
    private readonly IDictionary<string, KeyInfo> _keys = new Dictionary<string, KeyInfo>();

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

    public Task<IdentityResult> CreateAsync(IdentityToken token, CancellationToken cancellationToken)
    {
        _tokens[token.Id] = token;
        return Task.FromResult(IdentityResult.Success);
    }

    public Task<IdentityResult> DeleteAsync(IdentityToken token, CancellationToken cancellationToken)
    {
        _tokens.Remove(token.Id);
        return Task.FromResult(IdentityResult.Success);
    }

    Task<IdentityToken> ITokenStore<IdentityToken>.FindByIdAsync(string tokenId, CancellationToken cancellationToken)
        => Task.FromResult(_tokens.Values.Where(t => t.Id == tokenId).SingleOrDefault());

    public Task<IdentityToken> FindAsync(string purpose, string value, CancellationToken cancellationToken)
        => Task.FromResult(_tokens.Values.Where(t => t.Purpose == purpose && t.Payload == value).SingleOrDefault());

    public Task<DateTimeOffset> GetExpirationAsync(IdentityToken token, CancellationToken cancellationToken)
        => Task.FromResult(token.Expiration);

    public Task<string> GetStatusAsync(IdentityToken token, CancellationToken cancellationToken)
        => Task.FromResult(token.Status);

    public Task<string> GetSubjectAsync(IdentityToken token, CancellationToken cancellationToken)
        => Task.FromResult(token.Subject);

    public Task<IdentityToken> NewAsync(TokenInfo tokenInfo, CancellationToken cancellationToken)
        => Task.FromResult(new IdentityToken(tokenInfo));

    public Task<IdentityResult> RemoveAsync(string keyId, CancellationToken cancellationToken)
    {
        _keys.Remove(keyId);
        return Task.FromResult(IdentityResult.Success);
    }

    public Task SetExpirationAsync(IdentityToken token, DateTimeOffset expiration, CancellationToken cancellationToken)
    {
        token.Expiration = expiration;
        return Task.CompletedTask;
    }

    public Task SetStatusAsync(IdentityToken token, string status, CancellationToken cancellationToken)
    {
        token.Status = status;
        return Task.CompletedTask;
    }

    public Task SetSubjectAsync(IdentityToken token, string subject, CancellationToken cancellationToken)
    {
        token.Subject = subject;
        return Task.CompletedTask;
    }

    public Task<IdentityResult> UpdateAsync(IdentityToken token, CancellationToken cancellationToken)
    {
        _tokens[token.Id] = token;
        return Task.FromResult(IdentityResult.Success);
    }

    Task<KeyInfo> IKeyStore.FindByIdAsync(string keyId, CancellationToken cancellationToken)
    {
        _keys.TryGetValue(keyId, out var result);
        return Task.FromResult(result);
    }
}
