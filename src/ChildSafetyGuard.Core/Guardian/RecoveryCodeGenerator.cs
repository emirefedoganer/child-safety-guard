using System.Security.Cryptography;
using System.Text;

namespace ChildSafetyGuard.Core.Guardian;

public static class RecoveryCodeGenerator
{
    // 30 symbols; no 0/O, 1/I/L, U — avoids transcription mistakes. 20 symbols ≈ 98 bits of entropy.
    private const string Alphabet = "ABCDEFGHJKMNPQRSTVWXYZ23456789";
    private const int Groups = 4;
    private const int GroupSize = 5;

    public static string Generate()
    {
        var builder = new StringBuilder();
        for (var group = 0; group < Groups; group++)
        {
            if (group > 0)
            {
                builder.Append('-');
            }

            for (var i = 0; i < GroupSize; i++)
            {
                builder.Append(Alphabet[RandomNumberGenerator.GetInt32(Alphabet.Length)]);
            }
        }

        return builder.ToString();
    }

    public static string Normalize(string code) =>
        new(code.Where(char.IsLetterOrDigit).Select(char.ToUpperInvariant).ToArray());
}
