using ChildSafetyGuard.Core.Abstractions;
using ChildSafetyGuard.Core.Models;

namespace ChildSafetyGuard.Core.Guardian;

public enum AuthStatus
{
    Success,
    InvalidCredentials,
    LockedOut,
    NotInitialized,
}

public sealed record AuthResult(
    AuthStatus Status,
    GuardianSession? Session = null,
    DateTimeOffset? LockedUntilUtc = null,
    int RemainingAttempts = 0);

public sealed record RecoveryResult(AuthResult Auth, string? NewRecoveryCode);

/// <summary>
/// Guardian credentials: passphrase + one-time recovery code, with lockout.
/// Windows-level authorization (running elevated) is enforced separately by the host application.
/// </summary>
public sealed class GuardianManager
{
    public const int MaxFailedAttempts = 5;
    public const int MinPassphraseLength = 8;
    public const int MaxPassphraseLength = 128;
    public static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(15);
    public static readonly TimeSpan SessionLifetime = TimeSpan.FromMinutes(10);

    private readonly IStateStore _store;
    private readonly TimeProvider _time;
    private readonly int _iterations;

    public GuardianManager(IStateStore store, TimeProvider time, int hashIterations = SecretHasher.DefaultIterations)
    {
        _store = store;
        _time = time;
        _iterations = hashIterations;
    }

    public bool IsInitialized => _store.Load()?.Guardian is not null;

    /// <summary>Creates the guardian credential and returns the recovery code. The code is shown once and only its hash is stored.</summary>
    public string Initialize(string passphrase)
    {
        ValidatePassphrase(passphrase);

        var state = _store.Load() ?? new AppState();
        if (state.Guardian is not null)
        {
            throw new InvalidOperationException("A guardian is already configured.");
        }

        var recoveryCode = RecoveryCodeGenerator.Generate();
        state = state with
        {
            Guardian = new GuardianRecord
            {
                Passphrase = SecretHasher.Hash(passphrase, _iterations),
                RecoveryCode = SecretHasher.Hash(RecoveryCodeGenerator.Normalize(recoveryCode), _iterations),
                CreatedAtUtc = _time.GetUtcNow(),
            },
        };
        _store.Save(state);
        return recoveryCode;
    }

    public AuthResult Authenticate(string passphrase)
    {
        var state = _store.Load();
        if (state?.Guardian is null)
        {
            return new AuthResult(AuthStatus.NotInitialized);
        }

        var now = _time.GetUtcNow();
        var guardian = state.Guardian;
        if (guardian.LockedUntilUtc is { } until && until > now)
        {
            return new AuthResult(AuthStatus.LockedOut, LockedUntilUtc: until);
        }

        if (SecretHasher.Verify(passphrase, guardian.Passphrase))
        {
            if (guardian.FailedAttempts != 0 || guardian.LockedUntilUtc is not null)
            {
                _store.Save(state with { Guardian = guardian with { FailedAttempts = 0, LockedUntilUtc = null } });
            }

            return new AuthResult(AuthStatus.Success, new GuardianSession(now, SessionLifetime));
        }

        return RegisterFailure(state, guardian, now);
    }

    public AuthResult ChangePassphrase(string currentPassphrase, string newPassphrase)
    {
        ValidatePassphrase(newPassphrase);

        var auth = Authenticate(currentPassphrase);
        if (auth.Status != AuthStatus.Success)
        {
            return auth;
        }

        var state = _store.Load()!;
        var guardian = state.Guardian!;
        _store.Save(state with { Guardian = guardian with { Passphrase = SecretHasher.Hash(newPassphrase, _iterations) } });
        return auth;
    }

    /// <summary>
    /// Emergency recovery: a valid recovery code turns enforcement off, sets a new passphrase and issues a new recovery code.
    /// The caller is responsible for running the enforcement engine so firewall rules are removed immediately.
    /// </summary>
    public RecoveryResult Recover(string recoveryCode, string newPassphrase)
    {
        ValidatePassphrase(newPassphrase);

        var state = _store.Load();
        if (state?.Guardian is null)
        {
            return new RecoveryResult(new AuthResult(AuthStatus.NotInitialized), null);
        }

        var now = _time.GetUtcNow();
        var guardian = state.Guardian;
        if (guardian.LockedUntilUtc is { } until && until > now)
        {
            return new RecoveryResult(new AuthResult(AuthStatus.LockedOut, LockedUntilUtc: until), null);
        }

        var normalized = RecoveryCodeGenerator.Normalize(recoveryCode ?? string.Empty);
        if (guardian.RecoveryCode is null || !SecretHasher.Verify(normalized, guardian.RecoveryCode))
        {
            return new RecoveryResult(RegisterFailure(state, guardian, now), null);
        }

        var newCode = RecoveryCodeGenerator.Generate();
        _store.Save(state with
        {
            Guardian = new GuardianRecord
            {
                Passphrase = SecretHasher.Hash(newPassphrase, _iterations),
                RecoveryCode = SecretHasher.Hash(RecoveryCodeGenerator.Normalize(newCode), _iterations),
                CreatedAtUtc = guardian.CreatedAtUtc,
            },
            Policy = state.Policy with { EnforcementEnabled = false },
        });

        return new RecoveryResult(new AuthResult(AuthStatus.Success, new GuardianSession(now, SessionLifetime)), newCode);
    }

    private AuthResult RegisterFailure(AppState state, GuardianRecord guardian, DateTimeOffset now)
    {
        var attempts = guardian.FailedAttempts + 1;
        if (attempts >= MaxFailedAttempts)
        {
            var lockedUntil = now + LockoutDuration;
            _store.Save(state with { Guardian = guardian with { FailedAttempts = 0, LockedUntilUtc = lockedUntil } });
            return new AuthResult(AuthStatus.LockedOut, LockedUntilUtc: lockedUntil);
        }

        _store.Save(state with { Guardian = guardian with { FailedAttempts = attempts, LockedUntilUtc = null } });
        return new AuthResult(AuthStatus.InvalidCredentials, RemainingAttempts: MaxFailedAttempts - attempts);
    }

    private static void ValidatePassphrase(string passphrase)
    {
        if (string.IsNullOrEmpty(passphrase) || passphrase.Length < MinPassphraseLength)
        {
            throw new ArgumentException($"The passphrase must be at least {MinPassphraseLength} characters.", nameof(passphrase));
        }

        if (passphrase.Length > MaxPassphraseLength)
        {
            throw new ArgumentException($"The passphrase must be at most {MaxPassphraseLength} characters.", nameof(passphrase));
        }
    }
}
