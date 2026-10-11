using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using ChildSafetyGuard.Core;
using ChildSafetyGuard.Core.Abstractions;
using ChildSafetyGuard.Core.Models;
using Microsoft.Extensions.Logging;

namespace ChildSafetyGuard.Windows;

/// <summary>
/// Persists <see cref="AppState"/> as one DPAPI-encrypted file (machine scope) inside a directory that only
/// SYSTEM and Administrators can access. Writes are atomic; the service only ever reads.
/// </summary>
/// <remarks>
/// Machine-scope DPAPI lets both the SYSTEM service and the elevated CLI read the file. The entropy value below is
/// not a secret; real protection comes from the directory ACL. A local administrator can always read the data —
/// by design, the guardian is that administrator and the minor is a standard user.
/// </remarks>
public sealed class DpapiStateStore : IStateStore
{
    private const string FileName = "state.dat";
    private const string MutexName = @"Global\ChildSafetyGuard.StateFile";
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("ChildSafetyGuard/state/v1");

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly string _directory;
    private readonly string _path;
    private readonly ILogger<DpapiStateStore> _logger;

    public DpapiStateStore(string directory, ILogger<DpapiStateStore> logger)
    {
        _directory = directory;
        _path = Path.Combine(directory, FileName);
        _logger = logger;
    }

    public AppState? Load()
    {
        if (!File.Exists(_path))
        {
            return null;
        }

        try
        {
            var cipher = File.ReadAllBytes(_path);
            var plain = ProtectedData.Unprotect(cipher, Entropy, DataProtectionScope.LocalMachine);
            try
            {
                var state = JsonSerializer.Deserialize<AppState>(plain, JsonOptions)
                            ?? throw new StateStoreException("The configuration file is empty.");
                if (state.SchemaVersion > AppState.CurrentSchemaVersion)
                {
                    throw new StateStoreException(
                        $"The configuration was written by a newer version (schema {state.SchemaVersion}); update the software.");
                }

                return state;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plain);
            }
        }
        catch (CryptographicException ex)
        {
            throw new StateStoreException("The configuration could not be decrypted. It may have been copied from another machine or damaged.", ex);
        }
        catch (JsonException ex)
        {
            throw new StateStoreException("The configuration is damaged and could not be parsed.", ex);
        }
        catch (IOException ex)
        {
            throw new StateStoreException("The configuration file could not be read.", ex);
        }
    }

    public void Save(AppState state)
    {
        Directory.CreateDirectory(_directory);
        StateDirectorySecurity.Harden(_directory);

        var plain = JsonSerializer.SerializeToUtf8Bytes(state, JsonOptions);
        try
        {
            var cipher = ProtectedData.Protect(plain, Entropy, DataProtectionScope.LocalMachine);

            using var mutex = new Mutex(false, MutexName);
            try
            {
                if (!mutex.WaitOne(TimeSpan.FromSeconds(10)))
                {
                    throw new StateStoreException("Timed out waiting for another process to finish writing the configuration.");
                }
            }
            catch (AbandonedMutexException)
            {
                // The previous owner died mid-write; the atomic replace below keeps the file consistent.
            }

            try
            {
                var temp = _path + ".tmp";
                File.WriteAllBytes(temp, cipher);
                if (File.Exists(_path))
                {
                    File.Replace(temp, _path, destinationBackupFileName: null);
                }
                else
                {
                    File.Move(temp, _path);
                }
            }
            finally
            {
                mutex.ReleaseMutex();
            }

            _logger.LogDebug("Configuration saved.");
        }
        catch (IOException ex)
        {
            throw new StateStoreException("The configuration file could not be written.", ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
        }
    }
}
