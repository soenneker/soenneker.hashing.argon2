using Konscious.Security.Cryptography;
using System.Security.Cryptography;
using System;
using Soenneker.Utils.Random.Security;
using Soenneker.Extensions.String;
using System.Threading.Tasks;
using Soenneker.Extensions.Task;
using System.Diagnostics.Contracts;
using Soenneker.Extensions.Arrays.Bytes;

namespace Soenneker.Hashing.Argon2;

/// <summary>
/// A utility library for Argon2 hashing and verification
/// </summary>
public static class Argon2HashingUtil
{
    private const int _defaultSaltSize = 16;
    private const int _defaultHashSize = 32;
    private const int _defaultIterations = 4;
    private const int _defaultMemorySize = 65536;
    private const int _defaultParallelism = 2;

    /// <summary>
    /// Generates a secure Argon2id hash for a given plaintext password.
    /// </summary>
    /// <param name="password">The plaintext password to hash. Cannot be null or whitespace.</param>
    /// <param name="saltSize">The size of the salt in bytes. Default is 16 bytes.</param>
    /// <param name="hashSize">The size of the hash in bytes. Default is 32 bytes.</param>
    /// <param name="iterations">The number of iterations for the Argon2id algorithm. Default is 4.</param>
    /// <param name="memorySize">The memory size in KB for the Argon2id algorithm. Default is 65536 KB.</param>
    /// <param name="parallelism">The number of threads to use for the Argon2id algorithm. Default is 2.</param>
    /// <returns>A Base64-encoded string containing the salt and hash.</returns>
    [Pure]
    public static async ValueTask<string> Hash(
        string password,
        int saltSize = _defaultSaltSize,
        int hashSize = _defaultHashSize,
        int iterations = _defaultIterations,
        int memorySize = _defaultMemorySize,
        int parallelism = _defaultParallelism)
    {
        password.ThrowIfNullOrWhiteSpace();

        // Generate a random salt
        byte[] salt = RandomSecurityUtil.GetByteArray(saltSize);

        // Configure Argon2id
        using var argon2 = new Argon2id(password.ToBytes())
        {
            Salt = salt,
            DegreeOfParallelism = parallelism,
            MemorySize = memorySize,
            Iterations = iterations
        };

        // Generate the hash
        byte[] hash = await argon2.GetBytesAsync(hashSize).NoSync();

        // Combine salt and hash into a single span
        var combined = new byte[saltSize + hashSize];
        salt.CopyTo(combined, 0);
        hash.CopyTo(combined, saltSize);

        // Return base64 encoded result
        return combined.ToBase64String();
    }

    /// <summary>
    /// Verifies whether a given plaintext password matches a Base64-encoded Argon2id hash.
    /// </summary>
    /// <param name="password">The plaintext password to verify. Cannot be null or whitespace.</param>
    /// <param name="hash">The Base64-encoded hash to verify against. Cannot be null or whitespace.</param>
    /// <param name="saltSize">The size of the salt in bytes. Default is 16 bytes.</param>
    /// <param name="hashSize">The size of the hash in bytes. Default is 32 bytes.</param>
    /// <param name="iterations">The number of iterations for the Argon2id algorithm. Default is 4.</param>
    /// <param name="memorySize">The memory size in KB for the Argon2id algorithm. Default is 65536 KB.</param>
    /// <param name="parallelism">The number of threads to use for the Argon2id algorithm. Default is 2.</param>
    /// <returns>True if the password matches the hash; otherwise, false.</returns>
    [Pure]
    public static async ValueTask<bool> Verify(
        string password,
        string hash,
        int saltSize = _defaultSaltSize,
        int hashSize = _defaultHashSize,
        int iterations = _defaultIterations,
        int memorySize = _defaultMemorySize,
        int parallelism = _defaultParallelism)
    {
        password.ThrowIfNullOrWhiteSpace();
        hash.ThrowIfNullOrWhiteSpace();

        // Decode the hash
        byte[] hashBytes = hash.ToBytesFromBase64();

        if (hashBytes.Length < _defaultSaltSize + hashSize)
            return false; // Invalid hash length

        // Extract salt and original hash
        byte[] salt = hashBytes.AsSpan(0, saltSize).ToArray();
        byte[] originalHash = hashBytes.AsSpan(saltSize, hashSize).ToArray();

        // Configure Argon2id
        using var argon2 = new Argon2id(password.ToBytes())
        {
            Salt = salt,
            DegreeOfParallelism = parallelism,
            MemorySize = memorySize,
            Iterations = iterations
        };

        // Generate new hash
        byte[] newHash = await argon2.GetBytesAsync(hashSize).NoSync();

        // Compare the original hash with the new hash
        return CryptographicOperations.FixedTimeEquals(originalHash, newHash);
    }
}