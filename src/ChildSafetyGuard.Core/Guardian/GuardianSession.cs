namespace ChildSafetyGuard.Core.Guardian;

/// <summary>
/// Proof that the guardian authenticated moments ago. It can only be created by
/// <see cref="GuardianManager"/>, so policy-changing code cannot run without going through authentication.
/// </summary>
public sealed class GuardianSession
{
    internal GuardianSession(DateTimeOffset issuedAtUtc, TimeSpan lifetime)
    {
        ExpiresAtUtc = issuedAtUtc + lifetime;
    }

    public DateTimeOffset ExpiresAtUtc { get; }

    public bool IsValidAt(DateTimeOffset nowUtc) => nowUtc < ExpiresAtUtc;
}
