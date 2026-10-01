using Authly.Authorization;
using Authly.Models;
using Xunit;

namespace Authly.Tests
{
    public class PasswordHashingTests
    {
        private static User NewUser(string? passwordHash = null) => new() { UserName = "alice", PasswordHash = passwordHash };

        [Fact]
        public void Hash_ThenVerify_Succeeds()
        {
            var user = NewUser();
            user.PasswordHash = PasswordHashing.Hash(user, "S3cret!pass");

            Assert.True(PasswordHashing.IsHashed(user.PasswordHash));
            Assert.True(PasswordHashing.Verify(user, "S3cret!pass", out var needsRehash));
            Assert.False(needsRehash);
        }

        [Fact]
        public void Hash_IsSalted()
        {
            var user = NewUser();
            Assert.NotEqual(PasswordHashing.Hash(user, "same"), PasswordHashing.Hash(user, "same"));
        }

        [Theory]
        [InlineData("wrong")]
        [InlineData("")]
        [InlineData(null)]
        public void Verify_WrongOrEmptyPassword_Fails(string? password)
        {
            var user = NewUser();
            user.PasswordHash = PasswordHashing.Hash(user, "correct");

            Assert.False(PasswordHashing.Verify(user, password, out _));
        }

        [Theory]
        [InlineData("admin123")]
        [InlineData("user@example.com")] // legacy external-user placeholder
        [InlineData(null)]
        [InlineData("")]
        public void Verify_PlaintextOrMissingStoredValue_NeverMatches(string? stored)
        {
            // A legacy plaintext value must not be accepted as a password, even when typed verbatim
            var user = NewUser(stored);
            Assert.False(PasswordHashing.Verify(user, stored, out _));
        }

        [Theory]
        [InlineData("admin123", false)]
        [InlineData("QUJDRA==", false)]   // valid base64, not a hash
        [InlineData("", false)]
        [InlineData(null, false)]
        public void IsHashed_RejectsPlaintext(string? value, bool expected)
        {
            Assert.Equal(expected, PasswordHashing.IsHashed(value));
        }

        [Fact]
        public void GenerateRandomPassword_IsLongAndUnique()
        {
            var a = PasswordHashing.GenerateRandomPassword();
            var b = PasswordHashing.GenerateRandomPassword();

            Assert.Equal(24, a.Length);
            Assert.NotEqual(a, b);
        }
    }
}
