using AwesomeAssertions;
using Soenneker.Tests.FixturedUnit;
using System.Threading.Tasks;
using System;
using Xunit;


namespace Soenneker.Hashing.Argon2.Tests;

[Collection("Collection")]
public class Argon2HashingUtilTests : FixturedUnitTest
{
    public Argon2HashingUtilTests(Fixture fixture, ITestOutputHelper output) : base(fixture, output)
    {
    }

    [Fact]
    public async Task Hash_ShouldGenerateValidHash()
    {
        // Arrange
        var password = "SecurePassword123";

        // Act
        string hash = await Argon2HashingUtil.Hash(password);

        // Assert
        hash.Should().NotBeNullOrEmpty("a hash should be generated");
        hash.Should().NotBe(password, "the hash should not match the plain text password");
    }

    [Fact]
    public async Task Verify_ShouldReturnTrueForValidPassword()
    {
        // Arrange
        var password = "SecurePassword123";
        string hash = await Argon2HashingUtil.Hash(password);

        // Act
        bool isValid = await Argon2HashingUtil.Verify(password, hash);

        // Assert
        isValid.Should().BeTrue("the password matches the hash");
    }

    [Fact]
    public async Task Verify_ShouldReturnFalseForInvalidPassword()
    {
        // Arrange
        var password = "SecurePassword123";
        string hash = await Argon2HashingUtil.Hash(password);

        // Act
        bool isValid = await Argon2HashingUtil.Verify("WrongPassword", hash);

        // Assert
        isValid.Should().BeFalse("the password does not match the hash");
    }

    [Fact]
    public async Task Verify_ShouldReturnFalseForTamperedHash()
    {
        // Arrange
        var password = "SecurePassword123";
        string hash = await Argon2HashingUtil.Hash(password);

        // Tamper the hash
        char[] hashChars = hash.ToCharArray();
        hashChars[hashChars.Length - 1] = hashChars[hashChars.Length - 1] == 'A' ? 'B' : 'A'; // Modify the last character
        var tamperedHash = new string(hashChars);

        // Act
        bool isValid = await Argon2HashingUtil.Verify(password, tamperedHash);

        // Assert
        isValid.Should().BeFalse("a tampered hash should not validate");
    }

    [Fact]
    public async Task Hash_ShouldThrowExceptionForNullPassword()
    {
        // Arrange
        string password = null;

        // Act
        Func<Task> act = async () => await Argon2HashingUtil.Hash(password);

        // Assert
        await act.Should().ThrowAsync<ArgumentException>("a null password is invalid");
    }

    [Fact]
    public async Task Verify_ShouldThrowExceptionForNullPassword()
    {
        // Arrange
        string hash = await Argon2HashingUtil.Hash("SecurePassword123");
        string nullPassword = null;

        // Act
        Func<Task> act = async () => await Argon2HashingUtil.Verify(nullPassword, hash);

        // Assert
        await act.Should().ThrowAsync<ArgumentException>("a null password is invalid");
    }

    [Fact]
    public async Task Verify_ShouldThrowExceptionForNullHash()
    {
        // Arrange
        var password = "SecurePassword123";
        string nullHash = null;

        // Act
        Func<Task> act = async () => await Argon2HashingUtil.Verify(password, nullHash);

        // Assert
        await act.Should().ThrowAsync<ArgumentException>("a null hash is invalid");
    }

    [Fact]
    public async Task Verify_ShouldReturnFalseForShortValidBase64Hash()
    {
        // Arrange
        var password = "SecurePassword123";
        var shortValidBase64Hash = "aGVsbG8="; // "hello" in Base64, too short to be a valid hash

        // Act
        bool isValid = await Argon2HashingUtil.Verify(password, shortValidBase64Hash);

        // Assert
        isValid.Should().BeFalse("a Base64 string shorter than expected should not validate as a hash");
    }

    [Fact]
    public async Task Verify_ShouldReturnFalseForInvalidBase64Hash()
    {
        // Arrange
        var password = "SecurePassword123";
        var invalidBase64Hash = "!!invalid-base64!!"; // Invalid Base64 string

        // Act
        Func<Task> act = async () => await Argon2HashingUtil.Verify(password, invalidBase64Hash);

        // Assert
        await act.Should().ThrowAsync<FormatException>("an invalid Base64 string should throw a format exception");
    }

    [Fact]
    public async Task Hash_ShouldRespectCustomParameters()
    {
        // Arrange
        var password = "CustomParameterPassword";
        const int customSaltSize = 32;
        const int customHashSize = 64;
        var customIterations = 8;
        var customMemorySize = 131072;
        var customParallelism = 4;

        // Act
        string hash = await Argon2HashingUtil.Hash(password, customSaltSize, customHashSize, customIterations, customMemorySize, customParallelism);
        bool isValid = await Argon2HashingUtil.Verify(password, hash, customSaltSize, customHashSize, customIterations, customMemorySize, customParallelism);

        // Assert
        hash.Should().NotBeNullOrEmpty("a hash should be generated with custom parameters");
        isValid.Should().BeTrue("the hash should validate with custom parameters");
    }
}
