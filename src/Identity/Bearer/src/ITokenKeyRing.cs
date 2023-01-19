// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace Microsoft.AspNetCore.Identity;

using System.Text.Json;
using Microsoft.Extensions.Options;

/// <summary>
/// Represents a single key ring, each key ring should be in its own named options instance.
/// </summary>
public class KeyRingOptions
{
    internal IActiveKeyRingSelector? ActiveKeySelector { get; set; }

    /// <summary>
    /// Represents a list of key sources.
    /// </summary>
    public IList<IKeySource> KeySources { get; set; } = new List<IKeySource>();
}

internal class DefaultActiveKeySelector : IActiveKeyRingSelector
{
    /// <summary>
    /// Returns the first key that is active.
    /// </summary>
    /// <param name="keys"></param>
    /// <returns></returns>
    /// <exception cref="NotImplementedException"></exception>
    public Task<IKey?> SelectActiveAsync(IEnumerable<IKey> keys)
    {
        // Return the first non revoked active key.
        foreach (var key in keys)
        {
            var now = DateTimeOffset.UtcNow;
            if (!key.IsRevoked && now > key.ActivationDate && key.ExpirationDate > now)
            {
                return Task.FromResult<IKey?>(key);
            }
        }
        // Return null if we have no active keys
        return Task.FromResult<IKey?>(null);
    }
}

internal class KeyRingManager
{
    private readonly IOptionsMonitor<KeyRingOptions> _options;
    private readonly Dictionary<string, IKeyRing> _keyRingMap = new Dictionary<string, IKeyRing>();

    public KeyRingManager(IOptionsMonitor<KeyRingOptions> options)
    {
        _options = options;
    }

    private async Task<IKeyRing> BuildKeyRingAsync(string keyRingName)
    {
        var keyRingOptions = _options.Get(keyRingName);
        var keys = new List<IKey>();
        foreach (var source in keyRingOptions.KeySources)
        {
            keys.AddRange(await source.LoadKeysAsync());
        }
        return new KeyRing(keyRingOptions.ActiveKeySelector ?? new DefaultActiveKeySelector(), keys);
    }

    /// <summary>
    /// Omitting the key ring name uses the default key ring of string.Empty.
    /// </summary>
    /// <param name="keyRingName"></param>
    /// <returns></returns>
    public async Task<IKeyRing> GetKeyRingAsync(string? keyRingName = null)
    {
        keyRingName ??= string.Empty;
        if (!_keyRingMap.ContainsKey(keyRingName))
        {
            _keyRingMap[keyRingName] = await BuildKeyRingAsync(keyRingName);
        }
        return _keyRingMap[keyRingName];
    }
}

internal class ActualKeySource : IKeySource
{
    private readonly IKey _key;
    public ActualKeySource(IKey key) => _key = key;

    public Task<IEnumerable<IKey>> LoadKeysAsync()
        => Task.FromResult<IEnumerable<IKey>>(new[] { _key });
}

/// <summary>
/// Represents a key source
/// </summary>
public interface IKeySource
{
    /// <summary>
    /// Loads the keys from the source.
    /// </summary>
    /// <returns></returns>
    Task<IEnumerable<IKey>> LoadKeysAsync();
}

internal interface IActiveKeyRingSelector
{
    /// <summary>
    /// Select the key to be the active key.
    /// </summary>
    /// <param name="keys"></param>
    /// <returns></returns>
    Task<IKey?> SelectActiveAsync(IEnumerable<IKey> keys);
}

internal class KeyRing : IKeyRing
{
    private readonly IList<IKey> _keys = new List<IKey>();
    private readonly IActiveKeyRingSelector _selector;

    public KeyRing(IActiveKeyRingSelector selector, IList<IKey> keys)
    {
        _selector = selector;
        _keys = keys;
    }

    public async Task<IKey> GetActiveKeyAsync()
    {
        var active = await _selector.SelectActiveAsync(_keys);
        if (active == null)
        {
            throw new InvalidOperationException("There are no active keys in the key ring.");
        }
        return active;
    }

    public IEnumerable<IKey> GetAllKeys()
        => _keys;
}

internal interface IKeyRing
{
    /// <summary>
    /// Return the current active key
    /// </summary>
    Task<IKey> GetActiveKeyAsync();

    /// <summary>
    /// Returns all of the keys in the ring.
    /// </summary>
    /// <returns>An enumeration of all keys.</returns>
    IEnumerable<IKey> GetAllKeys();

    ///// <summary>
    ///// Creates a new key with the specified activation and expiration dates and persists
    ///// the new key to the underlying repository.
    ///// </summary>
    ///// <param name="activationDate">The date on which encryptions to this key may begin.</param>
    ///// <param name="expirationDate">The date after which encryptions to this key may no longer take place.</param>
    ///// <returns>The newly-created IKey instance.</returns>
    //IKey CreateNewKey(DateTimeOffset activationDate, DateTimeOffset expirationDate);

    ///// <summary>
    ///// Retrieves a token that signals that callers who have cached the return value of
    ///// GetAllKeys should clear their caches. This could be in response to a call to
    ///// CreateNewKey or RevokeKey, or it could be in response to some other external notification.
    ///// Callers who are interested in observing this token should call this method before the
    ///// corresponding call to GetAllKeys.
    ///// </summary>
    ///// <returns>
    ///// The cache expiration token. When an expiration notification is triggered, any
    ///// tokens previously returned by this method will become canceled, and tokens returned by
    ///// future invocations of this method will themselves not trigger until the next expiration
    ///// event.
    ///// </returns>
    ///// <remarks>
    ///// Implementations are free to return 'CancellationToken.None' from this method.
    ///// Since this token is never guaranteed to fire, callers should still manually
    ///// clear their caches at a regular interval.
    ///// </remarks>
    //CancellationToken GetCacheExpirationToken();

    ///// <summary>
    ///// Revokes a specific key and persists the revocation to the underlying repository.
    ///// </summary>
    ///// <param name="keyId">The id of the key to revoke.</param>
    ///// <param name="reason">An optional human-readable reason for revocation.</param>
    ///// <remarks>
    ///// This method will not mutate existing IKey instances. After calling this method,
    ///// all existing IKey instances should be discarded, and GetAllKeys should be called again.
    ///// </remarks>
    //void RevokeKey(string keyId, string? reason = null);

    ///// <summary>
    ///// Revokes all keys created before a specified date and persists the revocation to the
    ///// underlying repository.
    ///// </summary>
    ///// <param name="revocationDate">The revocation date. All keys with a creation date before
    ///// this value will be revoked.</param>
    ///// <param name="reason">An optional human-readable reason for revocation.</param>
    ///// <remarks>
    ///// This method will not mutate existing IKey instances. After calling this method,
    ///// all existing IKey instances should be discarded, and GetAllKeys should be called again.
    ///// </remarks>
    //void RevokeAllKeys(DateTimeOffset revocationDate, string? reason = null);
}

/// <summary>
/// Represents a key used to protect tokens.
/// </summary>
public interface IKey
{
    /// <summary>
    /// The date at which encryptions with this key can begin taking place.
    /// </summary>
    DateTimeOffset ActivationDate { get; }

    /// <summary>
    /// The date on which this key was created.
    /// </summary>
    DateTimeOffset CreationDate { get; }

    /// <summary>
    /// The date after which encryptions with this key may no longer take place.
    /// </summary>
    /// <remarks>
    /// An expired key may still be used to decrypt existing payloads.
    /// </remarks>
    DateTimeOffset ExpirationDate { get; }

    /// <summary>
    /// Returns a value stating whether this key was revoked.
    /// </summary>
    /// <remarks>
    /// A revoked key may still be used to decrypt existing payloads, but the payloads
    /// must be treated as tampered unless the application has some other assurance
    /// that the payloads are authentic.
    /// </remarks>
    bool IsRevoked { get; }

    /// <summary>
    /// The id of the key.
    /// </summary>
    string KeyId { get; }

    /// <summary>
    /// 
    /// </summary>
    byte[] Data { get; }
}

/// <summary>
/// 
/// </summary>
public class BaseKey : IKey
{
    /// <summary>
    /// 
    /// </summary>
    /// <param name="data"></param>
    /// <param name="expirationDate"></param>
    /// <param name="keyId"></param>
    /// <param name="activationDate"></param>
    /// <param name="creationDate"></param>
    public BaseKey(byte[] data, DateTimeOffset expirationDate, string? keyId = null, DateTimeOffset? activationDate = null, DateTimeOffset? creationDate = null)
    {
        KeyId = keyId ?? Guid.NewGuid().ToString();
        ActivationDate = activationDate ?? DateTimeOffset.UtcNow;
        CreationDate = creationDate ?? DateTimeOffset.UtcNow;
        ExpirationDate = expirationDate;
        Data = data;
    }

    /// <inheritdoc/>
    public DateTimeOffset ActivationDate { get; }

    /// <inheritdoc/>
    public DateTimeOffset CreationDate { get; }

    /// <inheritdoc/>
    public DateTimeOffset ExpirationDate { get; }

    /// <inheritdoc/>
    public bool IsRevoked { get; }

    /// <inheritdoc/>
    public string KeyId { get; }

    /// <inheritdoc/>
    public byte[] Data { get; }
}

internal interface IIdentityKeyDataSerializer
{
    string Serialize(SigningKeyInfo key);
    SigningKeyInfo Deserialize(KeyInfo key);

    string ProviderId { get; }
    string Format { get; }
}

/// <summary>
/// Json serializes the key.
/// </summary>
internal sealed class JsonKeySerializer : IIdentityKeyDataSerializer
{
    public const string ProviderId = "Json";
    public const string FormatVersion0 = "0";

    string IIdentityKeyDataSerializer.ProviderId => ProviderId;
    string IIdentityKeyDataSerializer.Format => FormatVersion0;

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Trimming", "IL2026:Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code", Justification = "<Pending>")]
    public SigningKeyInfo Deserialize(KeyInfo key)
    {
        // TODO: check for format/version usage?
        var data = JsonSerializer.Deserialize<IDictionary<string, string>>(key.Data);
        if (data == null)
        {
            throw new InvalidOperationException("Failed to json deserialize key Data");
        }
        return new JsonSigningKey(key.Id, data);
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Trimming", "IL2026:Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code", Justification = "<Pending>")]
    public string Serialize(SigningKeyInfo key)
        => JsonSerializer.Serialize(key.Data);
}

// TODO: data protection should be built in?
internal sealed class Base64KeySerializer : IIdentityKeyDataSerializer
{
    public const string ProviderId = "Base64";

    public const string FormatVersion0 = "0";

    string IIdentityKeyDataSerializer.ProviderId => ProviderId;
    string IIdentityKeyDataSerializer.Format => FormatVersion0;

    public SigningKeyInfo Deserialize(KeyInfo key)
    {
        return new Base64Key(key.Id, key.Data);
    }

    public string Serialize(SigningKeyInfo key)
    {
        var base64Key = Base64Key.ToBase64Key(key);
        if (base64Key == null)
        {
            throw new InvalidOperationException("key is not in expected base64 format.");
        }
        return base64Key.Key;
    }
}

internal abstract class SigningKeyInfo
{
    private readonly IDictionary<string, string> _data;

    public SigningKeyInfo(string id, IDictionary<string, string>? data = null)
    {
        Id = id;
        _data = data ?? new Dictionary<string, string>();
    }

    public string Id { get; private set; }

    public string this[string key] { get => _data[key]; set => _data[key] = value; }

    public IDictionary<string, string> Data { get => _data; }
}

internal class JsonSigningKey : SigningKeyInfo
{
    public JsonSigningKey(string id, IDictionary<string, string> data) : base(id, data) { }
}

internal class Base64Key : SigningKeyInfo
{
    public Base64Key(string id, string base64key) : base(id)
        => Key = base64key;

    public string Key { get => this["k"]; set => this["k"] = value; }

    public static Base64Key? ToBase64Key(SigningKeyInfo key)
    {
        if (key.Data.ContainsKey("k"))
        {
            return new Base64Key(key.Id, key["k"]);
        }
        return null;
    }
}

/// <summary>
/// Base class for a token key.
/// </summary>
public abstract class TokenKey
{
    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="id"></param>
    /// <param name="key"></param>
    /// <param name="created"></param>
    public TokenKey(string id, string key, DateTimeOffset created)
    {
        Id = id;
        Key = key;
        Created = created;
    }

    /// <summary>
    /// The Id of the key.
    /// </summary>
    public string Id { get; set; }

    /// <summary>
    /// The actual key.
    /// </summary>
    public string Key { get; set; }

    /// <summary>
    /// When the key was created.
    /// </summary>
    public DateTimeOffset Created { get; set; }
}

/// <summary>
/// Abstraction used to manage named keys used to for tokens.
/// </summary>
public interface ITokenKeyRing
{
    /// <summary>
    /// Get the current key id.
    /// </summary>
    Task<TokenKey> GetCurrentKeyAsync();

    /// <summary>
    /// Return a specific key.
    /// </summary>
    /// <param name="keyId">The id of the key to fetch.</param>
    /// <returns>The key ring.</returns>
    Task<TokenKey> GetKeyAsync(string keyId);

    /// <summary>
    /// Return all of the key ids.
    /// </summary>
    /// <returns>All of the key ids.</returns>
    Task<IEnumerable<TokenKey>> GetAllKeysAsync();
}

internal class SerializedSecret
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string? Secret { get; set; }

    /// <summary>
    /// If true, the secret has been DataProtected.
    /// </summary>
    public bool IsProtected { get; set; }
}

//internal class TokenKeyRing : ITokenKeyRing
//{
//    private readonly IDictionary<string, string> _keyDictionary = new Dictionary<string, string>();

//    public TokenKeyRing(IHostEnvironment hostingEnvironment)
//    {
//        // Create the keyring directory if one doesn't exist.
//        var keyRingDirectory = Path.Combine(hostingEnvironment.ContentRootPath, "keyring");
//        Directory.CreateDirectory(keyRingDirectory);

//        var directoryInfo = new DirectoryInfo(keyRingDirectory);
//        var filesOrdered = directoryInfo.EnumerateFiles("*.key")
//                            .OrderByDescending(d => d.CreationTime)
//                            .Select(d => d.Name)
//                            .ToList();

//        if (filesOrdered.Count == 0)
//        {
//            // TODO: Figure out how to create a key

//            //ProtectorAlgorithmHelper.GetAlgorithms(
//            //    ProtectorAlgorithmHelper.DefaultAlgorithm,
//            //    out SymmetricAlgorithm encryptionAlgorithm,
//            //    out KeyedHashAlgorithm signingAlgorithm,
//            //    out int derivationCount);
//            //encryptionAlgorithm.GenerateKey();

//            //var keyAsString = Convert.ToBase64String(encryptionAlgorithm.Key);
//            var keyAsString = Convert.ToBase64String(Guid.NewGuid().ToByteArray());
//            string keyId = Guid.NewGuid().ToString();
//            var keyFileName = Path.Combine(keyRingDirectory, keyId + ".key");
//            using (var file = File.CreateText(keyFileName))
//            {
//                file.WriteLine(keyAsString);
//            }

//            _keyDictionary.Add(keyId, keyAsString);

//            CurrentKeyId = keyId;

//            //encryptionAlgorithm.Clear();
//            //encryptionAlgorithm.Dispose();
//            //signingAlgorithm.Dispose();
//        }
//        else
//        {
//            foreach (var fileName in filesOrdered)
//            {
//                var keyFileName = Path.Combine(keyRingDirectory, fileName);
//                var key = File.ReadAllText(keyFileName);
//                string keyId = Path.GetFileNameWithoutExtension(fileName);
//                _keyDictionary.Add(keyId, key);
//                CurrentKeyId = keyId;
//            }
//        }
//    }

//    public string this[string keyId] { get => _keyDictionary[keyId]; }

//    public string CurrentKeyId { get; } = string.Empty;

//    public IEnumerable<string> GetAllKeyIds()
//        => _keyDictionary.Keys;
//}
