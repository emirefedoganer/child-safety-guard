namespace ChildSafetyGuard.Core.Models;

/// <summary>A salted, slow hash of a secret (guardian passphrase or recovery code).</summary>
public sealed record PasswordHash(string Algorithm, int Iterations, string SaltBase64, string HashBase64);

public sealed record GuardianRecord
{
    public required PasswordHash Passphrase { get; init; }

    /// <summary>Hash of the one-time recovery code. Null only if the guardian cleared it.</summary>
    public PasswordHash? RecoveryCode { get; init; }

    public int FailedAttempts { get; init; }
    public DateTimeOffset? LockedUntilUtc { get; init; }
    public DateTimeOffset CreatedAtUtc { get; init; }
}
