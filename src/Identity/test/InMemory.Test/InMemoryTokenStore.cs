// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Linq;
using Microsoft.AspNetCore.Identity.Test;

namespace Microsoft.AspNetCore.Identity.InMemory;

public class InMemoryTokenStore<TUser, TRole> :
    InMemoryStore<TUser, TRole>,
    ITokenStore<IdentityToken>
    where TRole : PocoRole
    where TUser : PocoUser
{
    private readonly IDictionary<string, IdentityToken> _tokens = new Dictionary<string, IdentityToken>();

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

    public Task<IdentityToken> FindAsync(string purpose, string value, CancellationToken cancellationToken)
        => Task.FromResult(_tokens.Values.Where(t => t.Purpose == purpose && t.Value == value).SingleOrDefault());

    public Task<IdentityResult> UpdateAsync(IdentityToken token, CancellationToken cancellationToken)
    {
        _tokens[token.Id] = token;
        return Task.FromResult(IdentityResult.Success);
    }
}
