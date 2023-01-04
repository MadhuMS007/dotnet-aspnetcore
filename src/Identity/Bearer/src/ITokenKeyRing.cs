// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace Microsoft.AspNetCore.Identity;

using System.Text.Json;

internal interface IIdentityKeyDataSerializer
{
    string Serialize(SigningKey key);
    SigningKey Deserialize(IdentityKeyData key);

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
    public SigningKey Deserialize(IdentityKeyData key)
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
    public string Serialize(SigningKey key)
        => JsonSerializer.Serialize(key.Data);
}

// TODO: data protection should be built in?
internal sealed class Base64KeySerializer : IIdentityKeyDataSerializer
{
    public const string ProviderId = "Base64";

    public const string FormatVersion0 = "0";

    string IIdentityKeyDataSerializer.ProviderId => ProviderId;
    string IIdentityKeyDataSerializer.Format => FormatVersion0;

    public SigningKey Deserialize(IdentityKeyData key)
    {
        return new Base64Key(key.Id, key.Data);
    }

    public string Serialize(SigningKey key)
    {
        var base64Key = Base64Key.ToBase64Key(key);
        if (base64Key == null)
        {
            throw new InvalidOperationException("key is not in expected base64 format.");
        }
        return base64Key.Key;
    }
}

internal abstract class SigningKey
{
    private readonly IDictionary<string, string> _data;

    public SigningKey(string id, IDictionary<string, string>? data = null)
    {
        Id = id;
        _data = data ?? new Dictionary<string, string>();
    }

    public string Id { get; private set; }

    public string this[string key] { get => _data[key]; set => _data[key] = value; }

    public IDictionary<string, string> Data { get => _data; }
}

internal class JsonSigningKey : SigningKey
{
    public JsonSigningKey(string id, IDictionary<string, string> data) : base(id, data) { }
}

internal class Base64Key : SigningKey
{
    public Base64Key(string id, string base64key) : base(id)
        => Key = base64key;

    public string Key { get => this["k"]; set => this["k"] = value; }

    public static Base64Key? ToBase64Key(SigningKey key)
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
