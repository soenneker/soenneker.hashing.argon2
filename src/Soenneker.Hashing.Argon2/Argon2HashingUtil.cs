using Konscious.Security.Cryptography;
using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Soenneker.Extensions.Arrays.Bytes;
using Soenneker.Extensions.String;
using Soenneker.Extensions.Task;
using Soenneker.Utils.Random.Security;

namespace Soenneker.Hashing.Argon2;

/// <summary>
/// Argon2id hashing + verification (PHC format).
/// </summary>
public static class Argon2HashingUtil
{
    private const int _defaultSaltBytes = 16;
    private const int _defaultHashBytes = 32;
    private const int _defaultTime = 3; // iterations
    private const int _defaultMemoryKiB = 131_072; // 128 MiB (in KiB, per Konscious)
    private const int _defaultParallelism = 2;
    private const int _maxSaltBytes = 64;
    private const int _maxHashBytes = 128;
    private const int _maxTime = 10;
    private const int _maxMemoryKiB = 262_144;
    private const int _maxParallelism = 16;

    /// <summary>
    /// Creates a PHC-formatted Argon2id record:
    /// <c>$argon2id$v=19$m=&lt;KiB&gt;,t=&lt;iter&gt;,p=&lt;par&gt;$&lt;saltB64&gt;$&lt;hashB64&gt;</c>
    /// </summary>
    /// <param name="password">The plaintext password to hash.</param>
    /// <param name="saltBytes">Salt bytes used by the password hash.</param>
    /// <param name="hashBytes">Hash bytes to encode or verify.</param>
    /// <param name="time">The iteration count.</param>
    /// <param name="memoryKiB">The memory cost in KiB.</param>
    /// <param name="parallelism">The degree of parallelism.</param>
    /// <returns>The encoded Argon2id record.</returns>
    public static async ValueTask<string> Hash(string password, int saltBytes = _defaultSaltBytes, int hashBytes = _defaultHashBytes, int time = _defaultTime,
        int memoryKiB = _defaultMemoryKiB, int parallelism = _defaultParallelism)
    {
        password.ThrowIfNullOrWhiteSpace();

        if (!ParametersAreSafe(saltBytes, hashBytes, time, memoryKiB, parallelism))
            throw new InvalidOperationException("Argon2 parameters exceed the supported safety limits.");

        byte[] salt = RandomSecurityUtil.GetByteArray(saltBytes);
        byte[] pwd = password.ToBytes(); // from Soenneker.Extensions.String
        byte[] hash = [];

        try
        {
            using var a2 = new Argon2id(pwd)
            {
                Salt = salt,
                Iterations = time,
                MemorySize = memoryKiB, // KiB
                DegreeOfParallelism = parallelism
            };

            hash = await a2.GetBytesAsync(hashBytes).NoSync();

            string saltB64 = salt.ToBase64String();
            string hashB64 = hash.ToBase64String();

            return $"$argon2id$v=19$m={memoryKiB},t={time},p={parallelism}${saltB64}${hashB64}";
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pwd);
            if (hash.Length > 0) 
                CryptographicOperations.ZeroMemory(hash);

            CryptographicOperations.ZeroMemory(salt);
        }
    }

    /// <summary>
    /// Verifies a PHC-formatted Argon2id record.
    /// Accepts: <c>$argon2id$v=19$m=...,t=...,p=...$&lt;saltB64&gt;$&lt;hashB64&gt;</c>
    /// </summary>
    /// <param name="password">The candidate plaintext password.</param>
    /// <param name="phc">The encoded Argon2id record returned by <see cref="Hash"/>.</param>
    /// <returns><see langword="true"/> when the password matches; otherwise, <see langword="false"/>.</returns>
    public static async ValueTask<bool> Verify(string password, string phc)
    {
        if (password.IsNullOrWhiteSpace() || phc.IsNullOrWhiteSpace() || phc.Length > 1024)
            return false;

        // parts: 0:"argon2id", 1:"v=19", 2:"m=..,t=..,p=..", 3:"saltB64", 4:"hashB64"
        string[] parts = phc.Split('$', StringSplitOptions.RemoveEmptyEntries);

        if (parts.Length != 5 || !parts[0].Equals("argon2id", StringComparison.Ordinal))
            return false;

        if (!parts[1].Equals("v=19", StringComparison.Ordinal))
            return false;

        int memoryKiB = 0, time = 0, parallelism = 0;
        string[] kvs = parts[2].Split(',', StringSplitOptions.RemoveEmptyEntries);

        for (int i = 0; i < kvs.Length; i++)
        {
            string kv = kvs[i];
            if (kv.StartsWith("m=", StringComparison.Ordinal) && !int.TryParse(kv.AsSpan(2), out memoryKiB))
                return false;
            if (kv.StartsWith("t=", StringComparison.Ordinal) && !int.TryParse(kv.AsSpan(2), out time))
                return false;
            if (kv.StartsWith("p=", StringComparison.Ordinal) && !int.TryParse(kv.AsSpan(2), out parallelism))
                return false;
        }

        if (memoryKiB <= 0 || time <= 0 || parallelism <= 0 || memoryKiB > _maxMemoryKiB || time > _maxTime || parallelism > _maxParallelism)
            return false;

        if (parts[3].Length > 128 || parts[4].Length > 256)
            return false;

        byte[] salt, expected;

        try
        {
            salt = Convert.FromBase64String(parts[3]);
            expected = Convert.FromBase64String(parts[4]);
        }
        catch
        {
            return false;
        }

        if (!ParametersAreSafe(salt.Length, expected.Length, time, memoryKiB, parallelism))
        {
            CryptographicOperations.ZeroMemory(salt);
            CryptographicOperations.ZeroMemory(expected);
            return false;
        }

        byte[] pwd = password.ToBytes();
        byte[] hash = [];

        try
        {
            using var a2 = new Argon2id(pwd)
            {
                Salt = salt,
                Iterations = time,
                MemorySize = memoryKiB,
                DegreeOfParallelism = parallelism
            };

            hash = await a2.GetBytesAsync(expected.Length).NoSync();
            return CryptographicOperations.FixedTimeEquals(hash, expected);
        }
        catch
        {
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pwd);

            if (hash.Length > 0)
                CryptographicOperations.ZeroMemory(hash);

            CryptographicOperations.ZeroMemory(salt);
            CryptographicOperations.ZeroMemory(expected);
        }
    }

    private static bool ParametersAreSafe(int saltBytes, int hashBytes, int time, int memoryKiB, int parallelism) =>
        saltBytes is >= 8 and <= _maxSaltBytes && hashBytes is >= 16 and <= _maxHashBytes && time is >= 1 and <= _maxTime &&
        memoryKiB is >= 8 and <= _maxMemoryKiB && parallelism is >= 1 and <= _maxParallelism;
}
