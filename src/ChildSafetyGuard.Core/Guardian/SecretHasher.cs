using System.Security.Cryptography;
using System.Text;
using ChildSafetyGuard.Core.Models;

namespace ChildSafetyGuard.Core.Guardian;

public static class SecretHasher
{
    public const string AlgorithmName = "PBKDF2-SHA256";
    public const int DefaultIterations = 310_000;
    private const int SaltSize = 16;
    private const int HashSize = 32;

    public static PasswordHash Hash(string secret, int iterations = DefaultIterations)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var hash = Derive(secret, salt, iterations);
        return new PasswordHash(AlgorithmName, iterations, Convert.ToBase64String(salt), Convert.ToBase64String(hash));
    }

    public static bool Verify(string secret, PasswordHash stored)
    {
        if (stored.Algorithm != AlgorithmName || stored.Iterations <= 0)
        {
            return false;
        }

        var salt = Convert.FromBase64String(stored.SaltBase64);
        var expected = Convert.FromBase64String(stored.HashBase64);
        var actual = Derive(secret, salt, stored.Iterations);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    private static byte[] Derive(string secret, byte[] salt, int iterations) =>
        Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(secret), salt, iterations, HashAlgorithmName.SHA256, HashSize);
}
