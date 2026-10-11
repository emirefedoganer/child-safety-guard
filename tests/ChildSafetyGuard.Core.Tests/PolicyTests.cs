using ChildSafetyGuard.Core.Guardian;
using ChildSafetyGuard.Core.Models;
using ChildSafetyGuard.Core.Policy;

namespace ChildSafetyGuard.Core.Tests;

public class PolicyValidatorTests
{
    private static IReadOnlyList<string> Validate(params BlockedApplication[] apps) =>
        TestData.Validator().Validate(new PolicyDocument { BlockedApplications = apps });

    private static BlockedApplication App(string id, params string[] patterns) => new(id, "Test app", patterns);

    [Fact]
    public void DefaultPolicy_IsValid() =>
        Assert.Empty(TestData.Validator().Validate(PolicyDocument.CreateDefault()));

    [Theory]
    [InlineData(@"%LOCALAPPDATA%\Game\app-*\game.exe")]
    [InlineData(@"C:\Games\Fun\fun.exe")]
    [InlineData(@"%ProgramFiles%\Thing\thing-*.exe")]
    public void AcceptsReasonablePatterns(string pattern) => Assert.Empty(Validate(App("fun", pattern)));

    [Theory]
    [InlineData(@"*.exe")]
    [InlineData(@"C:\Users\*\*.exe")]                      // file name is only a wildcard
    [InlineData(@"C:\Games\..\Windows\notepad.exe")]       // traversal
    [InlineData(@"\\server\share\tool.exe")]               // UNC
    [InlineData(@"relative\tool.exe")]                     // not rooted
    [InlineData(@"%SystemRoot%\System32\anything.exe")]    // protected folder
    [InlineData(@"C:\Games\Fun\readme.txt")]               // not an executable
    [InlineData(@"*\Fun\fun.exe")]                          // wildcard in the first segment
    public void RejectsDangerousOrMalformedPatterns(string pattern) =>
        Assert.NotEmpty(Validate(App("fun", pattern)));

    [Fact]
    public void RejectsBadIds_Duplicates_AndEmptyPatternLists()
    {
        Assert.NotEmpty(Validate(App("Bad Id", @"C:\a\b.exe")));
        Assert.NotEmpty(Validate(App("dup", @"C:\a\b.exe"), App("dup", @"C:\a\c.exe")));
        Assert.NotEmpty(Validate(new BlockedApplication("empty", "Empty", Array.Empty<string>())));
    }

    [Fact]
    public void RejectsInvalidProfilesAndWatchedProcessNames()
    {
        var policy = new PolicyDocument
        {
            TargetProfiles = new[] { @"..\other" },
            ExtraWatchedProcessNames = new[] { @"C:\tools\x.exe" },
        };

        Assert.Equal(2, TestData.Validator().Validate(policy).Count);
    }

    [Theory]
    [InlineData(@"C:\Windows\System32\svchost.exe", true)]
    [InlineData(@"C:\Windows\Temp\foo.exe", true)]
    [InlineData(@"D:\Anywhere\MsMpEng.exe", true)]
    [InlineData(@"C:\Program Files\ChildSafetyGuard\service\ChildSafetyGuard.Service.exe", true)]
    [InlineData(@"C:\Users\kid\AppData\Local\Discord\app-1.0.9\Discord.exe", false)]
    public void ProtectedPaths(string path, bool expected) =>
        Assert.Equal(expected, TestData.Validator().IsProtectedPath(path));
}

public class PolicyManagerTests
{
    private static PolicyManager Create(InMemoryStateStore store, ManualTimeProvider time) =>
        new(store, TestData.Validator(), time);

    [Fact]
    public void Changes_RequireALiveSession()
    {
        var (store, time, _, session) = TestData.Guarded();
        var manager = Create(store, time);

        manager.SetEnforcement(session, true);
        Assert.True(store.Current!.Policy.EnforcementEnabled);

        time.Advance(GuardianManager.SessionLifetime + TimeSpan.FromSeconds(1));
        Assert.Throws<UnauthorizedAccessException>(() => manager.SetEnforcement(session, false));
        Assert.True(store.Current.Policy.EnforcementEnabled);
    }

    [Fact]
    public void Changes_WithoutAGuardian_AreRefused()
    {
        var (_, time, _, session) = TestData.Guarded();
        var emptyStore = new InMemoryStateStore();

        Assert.Throws<InvalidOperationException>(() => Create(emptyStore, time).SetEnforcement(session, true));
    }

    [Fact]
    public void AddOrUpdateApplication_ReplacesById_AndRejectsInvalidInput()
    {
        var (store, time, _, session) = TestData.Guarded();
        var manager = Create(store, time);

        manager.AddOrUpdateApplication(session, new BlockedApplication("game", "Game", new[] { @"C:\Games\a.exe" }));
        manager.AddOrUpdateApplication(session, new BlockedApplication("game", "Game v2", new[] { @"C:\Games\b.exe" }));

        var games = store.Current!.Policy.BlockedApplications.Where(a => a.Id == "game").ToList();
        Assert.Single(games);
        Assert.Equal("Game v2", games[0].DisplayName);

        var before = store.SaveCount;
        var ex = Assert.Throws<PolicyValidationException>(() =>
            manager.AddOrUpdateApplication(session, new BlockedApplication("svc", "Svc", new[] { @"%SystemRoot%\System32\svchost.exe" })));
        Assert.NotEmpty(ex.Errors);
        Assert.Equal(before, store.SaveCount); // an invalid change is never persisted
    }

    [Fact]
    public void Remove_And_Toggle_ReportWhetherTheApplicationExists()
    {
        var (store, time, _, session) = TestData.Guarded();
        var manager = Create(store, time);

        Assert.True(manager.SetApplicationEnabled(session, "discord", false));
        Assert.False(store.Current!.Policy.BlockedApplications.Single(a => a.Id == "discord").Enabled);
        Assert.False(manager.SetApplicationEnabled(session, "nope", true));

        Assert.True(manager.RemoveApplication(session, "discord"));
        Assert.False(manager.RemoveApplication(session, "discord"));
    }
}
