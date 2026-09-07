using Konscious.Security.Cryptography;
using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Soenneker.Extensions.String;
using Soenneker.Extensions.Task;
using Soenneker.Hashing.Phc;
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
    private const string _identifier = "argon2id";
    private const int _version = 19;

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

            var record = new PhcString(_identifier, _version,
                [new PhcParameter("m", memoryKiB.ToString(CultureInfo.InvariantCulture)), new PhcParameter("t", time.ToString(CultureInfo.InvariantCulture)),
                    new PhcParameter("p", parallelism.ToString(CultureInfo.InvariantCulture))],
                Convert.ToBase64String(salt).TrimEnd('='), Convert.ToBase64String(hash).TrimEnd('='));

            return PhcFormatter.Format(record);
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

        if (!PhcFormatter.TryParse(phc, out PhcString? parsed))
            return false;

        PhcString record = parsed!;
        if (!record.Identifier.Equals(_identifier, StringComparison.Ordinal) || record.Version != _version || record.Parameters.Count != 3 ||
            record.Salt is null || record.Hash is null || !record.TryGetParameter("m", out string? memoryText) ||
            !record.TryGetParameter("t", out string? timeText) || !record.TryGetParameter("p", out string? parallelismText))
            return false;

        if (!int.TryParse(memoryText, NumberStyles.None, CultureInfo.InvariantCulture, out int memoryKiB) ||
            !int.TryParse(timeText, NumberStyles.None, CultureInfo.InvariantCulture, out int time) ||
            !int.TryParse(parallelismText, NumberStyles.None, CultureInfo.InvariantCulture, out int parallelism))
            return false;

        if (memoryKiB <= 0 || time <= 0 || parallelism <= 0 || memoryKiB > _maxMemoryKiB || time > _maxTime || parallelism > _maxParallelism)
            return false;

        if (record.Salt.Length > 128 || record.Hash.Length > 256)
            return false;

        byte[] salt, expected;

        try
        {
            salt = Convert.FromBase64String(PadBase64(record.Salt));
            expected = Convert.FromBase64String(PadBase64(record.Hash));
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

    private static string PadBase64(string value) => value.PadRight(value.Length + (4 - value.Length % 4) % 4, '=');
}
