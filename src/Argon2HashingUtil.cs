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

    /// <summary>
    /// Creates a PHC-formatted Argon2id record:
    /// <c>$argon2id$v=19$m=&lt;KiB&gt;,t=&lt;iter&gt;,p=&lt;par&gt;$&lt;saltB64&gt;$&lt;hashB64&gt;</c>
    /// </summary>
    public static async ValueTask<string> HashToPhc(string password, int saltBytes = _defaultSaltBytes, int hashBytes = _defaultHashBytes, int time = _defaultTime,
        int memoryKiB = _defaultMemoryKiB, int parallelism = _defaultParallelism)
    {
        password.ThrowIfNullOrWhiteSpace();

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
    public static async ValueTask<bool> VerifyPhc(string password, string phc)
    {
        if (password.IsNullOrWhiteSpace() || phc.IsNullOrWhiteSpace())
            return false;

        // parts: 0:"argon2id", 1:"v=19", 2:"m=..,t=..,p=..", 3:"saltB64", 4:"hashB64"
        string[] parts = phc.Split('$', StringSplitOptions.RemoveEmptyEntries);

        if (parts.Length != 5 || !parts[0].Equals("argon2id", StringComparison.Ordinal))
            return false;

        if (!parts[1].StartsWith("v=19", StringComparison.Ordinal))
            return false;

        int memoryKiB = 0, time = 0, parallelism = 0;
        string[] kvs = parts[2].Split(',', StringSplitOptions.RemoveEmptyEntries);

        for (int i = 0; i < kvs.Length; i++)
        {
            string kv = kvs[i];
            if (kv.StartsWith("m=", StringComparison.Ordinal))
                memoryKiB = int.Parse(kv.AsSpan(2));
            else if (kv.StartsWith("t=", StringComparison.Ordinal))
                time = int.Parse(kv.AsSpan(2));
            else if (kv.StartsWith("p=", StringComparison.Ordinal))
                parallelism = int.Parse(kv.AsSpan(2));
        }

        if (memoryKiB <= 0 || time <= 0 || parallelism <= 0)
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
}