[![](https://img.shields.io/nuget/v/soenneker.hashing.argon2.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.hashing.argon2/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.hashing.argon2/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.hashing.argon2/actions/workflows/publish-package.yml)
[![](https://img.shields.io/nuget/dt/soenneker.hashing.argon2.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.hashing.argon2/)

# ![](https://user-images.githubusercontent.com/4441470/224455560-91ed3ee7-f510-4041-a8d2-3fc093025112.png) Soenneker.Hashing.Argon2
### A utility library for Argon2 hashing and verification

### Features
- **Password Hashing**: Generates a secure, Base64-encoded hash for a plaintext password.
- **Password Verification**: Verifies a plaintext password against a hashed value.
- Fully customizable parameters for salt size, hash size, iterations, memory usage, and parallelism.


## Installation

```
dotnet add package Soenneker.Hashing.Argon2
```

### Usage

#### 1. Hashing a Password
```csharp
string password = "SecurePassword123";
string hash = await Argon2HashingUtil.Hash(password);

// Result: A Base64-encoded hash string
Console.WriteLine(hash);
```

#### 2. Verifying a Password
```csharp
string password = "SecurePassword123";
string hash = await Argon2HashingUtil.Hash(password);

bool isValid = await Argon2HashingUtil.Verify(password, hash);

// Result: True if the password matches the hash
Console.WriteLine(isValid ? "Password is valid!" : "Invalid password.");
```

#### 3. Custom Parameters
```csharp
string password = "CustomPassword";
int saltSize = 32;       // Custom salt size (bytes)
int hashSize = 64;       // Custom hash size (bytes)
int iterations = 8;      // Custom iteration count
int memorySize = 131072; // Custom memory size (KB)
int parallelism = 4;     // Custom thread count

string hash = await Argon2HashingUtil.Hash(password, saltSize, hashSize, iterations, memorySize, parallelism);
bool isValid = await Argon2HashingUtil.Verify(password, hash, saltSize, hashSize, iterations, memorySize, parallelism);
```

---

### Default Parameters
- **Salt Size**: 16 bytes
- **Hash Size**: 32 bytes
- **Iterations**: 4
- **Memory Size**: 65536 KB
- **Parallelism**: 2