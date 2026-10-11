using ChildSafetyGuard.Core.Guardian;
using ChildSafetyGuard.Core.Models;

namespace ChildSafetyGuard.Core.Tests;

public class GuardianManagerTests
{
    [Fact]
    public void Initialize_StoresOnlyHashes_AndReturnsRecoveryCodeOnce()
    {
        var store = new InMemoryStateStore();
        var guardian = new GuardianManager(store, new ManualTimeProvider(), TestData.FastHashIterations);

        var code = guardian.Initialize(TestData.Passphrase);

        Assert.Matches("^[A-Z2-9]{5}(-[A-Z2-9]{5}){3}$", code);
        var record = store.Current!.Guardian!;
        Assert.DoesNotContain(TestData.Passphrase, record.Passphrase.HashBase64);
        Assert.NotNull(record.RecoveryCode);
        Assert.False(store.Current.Policy.EnforcementEnabled); // nothing is enforced until the guardian opts in
    }

    [Fact]
    public void Initialize_RejectsShortPassphrase_AndSecondInitialization()
    {
        var store = new InMemoryStateStore();
        var guardian = new GuardianManager(store, new ManualTimeProvider(), TestData.FastHashIterations);

        Assert.Throws<ArgumentException>(() => guardian.Initialize("short"));
        guardian.Initialize(TestData.Passphrase);
        Assert.Throws<InvalidOperationException>(() => guardian.Initialize(TestData.Passphrase));
    }

    [Fact]
    public void Authenticate_CorrectPassphrase_ReturnsSessionValidForTenMinutes()
    {
        var (_, time, guardian, _) = TestData.Guarded();

        var result = guardian.Authenticate(TestData.Passphrase);

        Assert.Equal(AuthStatus.Success, result.Status);
        Assert.True(result.Session!.IsValidAt(time.GetUtcNow().AddMinutes(9)));
        Assert.False(result.Session.IsValidAt(time.GetUtcNow().AddMinutes(11)));
    }

    [Fact]
    public void Authenticate_WrongPassphrase_CountsDownThenLocksOut()
    {
        var (_, time, guardian, _) = TestData.Guarded();

        for (var attempt = 1; attempt < GuardianManager.MaxFailedAttempts; attempt++)
        {
            var failed = guardian.Authenticate("wrong passphrase");
            Assert.Equal(AuthStatus.InvalidCredentials, failed.Status);
            Assert.Equal(GuardianManager.MaxFailedAttempts - attempt, failed.RemainingAttempts);
        }

        var locked = guardian.Authenticate("wrong passphrase");
        Assert.Equal(AuthStatus.LockedOut, locked.Status);

        // Even the correct passphrase is refused while locked.
        Assert.Equal(AuthStatus.LockedOut, guardian.Authenticate(TestData.Passphrase).Status);

        time.Advance(GuardianManager.LockoutDuration + TimeSpan.FromSeconds(1));
        Assert.Equal(AuthStatus.Success, guardian.Authenticate(TestData.Passphrase).Status);
    }

    [Fact]
    public void Authenticate_Success_ResetsFailureCounter()
    {
        var (store, _, guardian, _) = TestData.Guarded();

        guardian.Authenticate("wrong passphrase");
        guardian.Authenticate("wrong passphrase");
        guardian.Authenticate(TestData.Passphrase);

        Assert.Equal(0, store.Current!.Guardian!.FailedAttempts);
    }

    [Fact]
    public void Authenticate_BeforeSetup_ReportsNotInitialized()
    {
        var guardian = new GuardianManager(new InMemoryStateStore(), new ManualTimeProvider(), TestData.FastHashIterations);

        Assert.Equal(AuthStatus.NotInitialized, guardian.Authenticate(TestData.Passphrase).Status);
    }

    [Fact]
    public void ChangePassphrase_RequiresCurrentPassphrase()
    {
        var (_, _, guardian, _) = TestData.Guarded();

        Assert.Equal(AuthStatus.InvalidCredentials, guardian.ChangePassphrase("not the passphrase", "a brand new passphrase").Status);
        Assert.Equal(AuthStatus.Success, guardian.ChangePassphrase(TestData.Passphrase, "a brand new passphrase").Status);

        Assert.Equal(AuthStatus.InvalidCredentials, guardian.Authenticate(TestData.Passphrase).Status);
        Assert.Equal(AuthStatus.Success, guardian.Authenticate("a brand new passphrase").Status);
    }

    [Fact]
    public void Recover_WithValidCode_DisablesEnforcement_SetsNewPassphrase_AndRotatesCode()
    {
        var store = new InMemoryStateStore();
        var guardian = new GuardianManager(store, new ManualTimeProvider(), TestData.FastHashIterations);
        var code = guardian.Initialize(TestData.Passphrase);
        store.Current = store.Current! with { Policy = store.Current.Policy with { EnforcementEnabled = true } };

        var result = guardian.Recover(code.ToLowerInvariant().Replace("-", " "), "another long passphrase");

        Assert.Equal(AuthStatus.Success, result.Auth.Status);
        Assert.NotNull(result.NewRecoveryCode);
        Assert.NotEqual(code, result.NewRecoveryCode);
        Assert.False(store.Current!.Policy.EnforcementEnabled);
        Assert.Equal(AuthStatus.Success, guardian.Authenticate("another long passphrase").Status);

        // The old code no longer works.
        Assert.Equal(AuthStatus.InvalidCredentials, guardian.Recover(code, "yet another passphrase").Auth.Status);
    }

    [Fact]
    public void Recover_WithWrongCode_CountsTowardsLockout()
    {
        var (_, _, guardian, _) = TestData.Guarded();

        AuthResult last = new(AuthStatus.Success);
        for (var i = 0; i < GuardianManager.MaxFailedAttempts; i++)
        {
            last = guardian.Recover("AAAAA-AAAAA-AAAAA-AAAAA", "another long passphrase").Auth;
        }

        Assert.Equal(AuthStatus.LockedOut, last.Status);
    }
}

public class SecretHasherTests
{
    [Fact]
    public void Verify_AcceptsOriginal_RejectsOthers_AndSaltsDiffer()
    {
        var first = SecretHasher.Hash("hunter2-hunter2", 1_000);
        var second = SecretHasher.Hash("hunter2-hunter2", 1_000);

        Assert.True(SecretHasher.Verify("hunter2-hunter2", first));
        Assert.False(SecretHasher.Verify("hunter3-hunter3", first));
        Assert.NotEqual(first.SaltBase64, second.SaltBase64);
        Assert.NotEqual(first.HashBase64, second.HashBase64);
    }

    [Fact]
    public void Verify_RejectsUnknownAlgorithm()
    {
        var hash = SecretHasher.Hash("hunter2-hunter2", 1_000) with { Algorithm = "MD5" };

        Assert.False(SecretHasher.Verify("hunter2-hunter2", hash));
    }
}
