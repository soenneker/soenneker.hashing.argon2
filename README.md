[![](https://img.shields.io/nuget/v/soenneker.hashing.argon2.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.hashing.argon2/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.hashing.argon2/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.hashing.argon2/actions/workflows/publish-package.yml)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.hashing.argon2/build-and-test.yml?style=for-the-badge&label=build)](https://github.com/soenneker/soenneker.hashing.argon2/actions/workflows/build-and-test.yml)
[![](https://img.shields.io/nuget/dt/soenneker.hashing.argon2.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.hashing.argon2/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.hashing.argon2/codeql.yml?label=CodeQL&style=for-the-badge)](https://github.com/soenneker/soenneker.hashing.argon2/actions/workflows/codeql.yml)

# Soenneker.Hashing.Argon2

Hashes passwords with Argon2id and stores the salt, work factors, and derived hash in one PHC-style string. Verification reads the parameters from that string and compares derived bytes in constant time.

## Installation

```bash
dotnet add package Soenneker.Hashing.Argon2
```

## Hash and verify a password

```csharp
using Soenneker.Hashing.Argon2;

string storedHash = await Argon2HashingUtil.Hash(password);

bool valid = await Argon2HashingUtil.Verify(candidatePassword, storedHash);
```

Store `storedHash` exactly as returned. It has this shape:

```text
$argon2id$v=19$m=131072,t=3,p=2$<salt>$<hash>
```

Each call to `Hash()` generates a new cryptographically secure 16-byte salt, so the same password produces different records. The defaults derive 32 bytes using three iterations, 128 MiB of memory, and parallelism of two.

## Choose work factors deliberately

```csharp
string storedHash = await Argon2HashingUtil.Hash(
    password,
    saltBytes: 16,
    hashBytes: 32,
    time: 4,
    memoryKiB: 262_144,
    parallelism: 4);
```

Tune work factors on production-class hardware and measure authentication latency under expected concurrency. Increasing memory applies per concurrent hash operation, not per process.

To prevent stored or attacker-controlled records from requesting unbounded work, hashing and verification accept salt sizes from 8–64 bytes, derived hashes from 16–128 bytes, 1–10 iterations, 8–262,144 KiB of memory, and parallelism from 1–16. `Hash()` throws `InvalidOperationException` outside those limits; `Verify()` returns `false` for malformed or excessive records.

`Verify()` also returns `false` for empty inputs, invalid Base64, unsupported versions, and mismatched passwords. Password and derived-key byte buffers are cleared after use. Applications should still rate-limit authentication attempts and avoid logging plaintext passwords or hash records.
