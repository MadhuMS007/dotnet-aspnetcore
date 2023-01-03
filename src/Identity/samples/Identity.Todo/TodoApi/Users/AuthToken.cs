// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace TodoApi;

// DTO representing the response returned from the token endpoint
public record AuthToken(string AccessToken, string RefreshToken);
