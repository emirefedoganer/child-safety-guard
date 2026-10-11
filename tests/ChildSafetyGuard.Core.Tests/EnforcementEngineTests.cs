using ChildSafetyGuard.Core.Accounts;
using ChildSafetyGuard.Core.Enforcement;
using ChildSafetyGuard.Core.Models;
using Microsoft.Extensions.Logging.Abstractions;

namespace ChildSafetyGuard.Core.Tests;

public class EnforcementEngineTests
{
    private const string DiscordExe = @"C:\Users\kid\AppData\Local\Discord\app-1.0.9002\Discord.exe";
    private const string DiscordUpdater = @"C:\Users\kid\AppData\Local\Discord\Update.exe";

    private sealed class Rig
    {
        public InMemoryStateStore Store { get; }
        public FakeFirewall Firewall { get; } = new();
        public FakeResolver Resolver { get; } = new();
        public FakeInspector Inspector { get; } = new();
        public FakeInventory Inventory { get; } = new();
        public RecordingSink Sink { get; } = new();
        public FakeAccounts Accounts { get; } = new();
        public EnforcementEngine Engine { get; }

        public Rig(bool enforcementEnabled = true)
        {
            Store = TestData.Guarded().Store;
            Store.Current = Store.Current! with { Policy = Store.Current.Policy with { EnforcementEnabled = enforcementEnabled } };
            Resolver.PathsByApplicationId["discord"] = new[] { DiscordExe, DiscordUpdater };
            Engine = new EnforcementEngine(
                Store, Resolver, Firewall, Inspector, Inventory, Sink, TestData.Validator(), NullLogger<EnforcementEngine>.Instance,
                accounts: Accounts);
        }

        public void UpdatePolicy(Func<PolicyDocument, PolicyDocument> change) =>
            Store.Current = Store.Current! with { Policy = change(Store.Current.Policy) };
    }

    [Fact]
    public void EnabledPolicy_CreatesBlockRules_AndIsIdempotent()
    {
        var rig = new Rig();

        var first = rig.Engine.RunOnce();
        var second = rig.Engine.RunOnce();

        Assert.True(first.Enforced);
        Assert.Equal(2, first.RulesAdded);
        Assert.Equal(2, rig.Firewall.Rules.Count);
        Assert.All(rig.Firewall.Rules, r => Assert.True(r.IsBlock && r.IsOutbound && r.Enabled));
        Assert.Equal(0, second.RulesAdded);
        Assert.Equal(0, second.RulesRemoved);
    }

    [Fact]
    public void RestartingTheService_ReappliesRulesThatWereRemovedWhileItWasDown()
    {
        var rig = new Rig();
        rig.Engine.RunOnce();
        rig.Firewall.Rules.Clear(); // someone with admin rights deleted them

        var report = new EnforcementEngine(
            rig.Store, rig.Resolver, rig.Firewall, rig.Inspector, rig.Inventory, rig.Sink, TestData.Validator(), NullLogger<EnforcementEngine>.Instance).RunOnce();

        Assert.Equal(2, report.RulesAdded);
    }

    [Fact]
    public void DisablingEnforcement_RemovesEveryManagedRule()
    {
        var rig = new Rig();
        rig.Engine.RunOnce();

        rig.UpdatePolicy(p => p with { EnforcementEnabled = false });
        var report = rig.Engine.RunOnce();

        Assert.Equal(2, report.RulesRemoved);
        Assert.Empty(rig.Firewall.Rules);
    }

    [Fact]
    public void WhenTheApplicationUpdatesToANewFolder_TheRuleMovesWithIt()
    {
        var rig = new Rig();
        rig.Engine.RunOnce();

        rig.Resolver.PathsByApplicationId["discord"] = new[] { @"C:\Users\kid\AppData\Local\Discord\app-1.0.9003\Discord.exe", DiscordUpdater };
        var report = rig.Engine.RunOnce();

        Assert.Equal(1, report.RulesAdded);
        Assert.Equal(1, report.RulesRemoved);
        Assert.Contains(rig.Firewall.Rules, r => r.ProgramPath.Contains("9003"));
        Assert.DoesNotContain(rig.Firewall.Rules, r => r.ProgramPath.Contains("9002"));
    }

    [Fact]
    public void InvalidPolicy_LeavesExistingRulesUntouched()
    {
        var rig = new Rig();
        rig.Engine.RunOnce();
        var before = rig.Firewall.Rules.ToList();

        rig.UpdatePolicy(p => p with { BlockedApplications = new[] { new BlockedApplication("BAD ID", "x", new[] { @"C:\a.exe" }) } });
        var report = rig.Engine.RunOnce();

        Assert.True(report.Configured);
        Assert.False(report.Enforced);
        Assert.NotEmpty(report.Problems);
        Assert.Equal(before, rig.Firewall.Rules);
    }

    [Fact]
    public void UnreadableState_FailsStatic_WithoutThrowing()
    {
        var rig = new Rig();
        rig.Engine.RunOnce();
        var before = rig.Firewall.Rules.ToList();

        rig.Store.Unreadable = true;
        var report = rig.Engine.RunOnce();

        Assert.False(report.Configured);
        Assert.Equal(before, rig.Firewall.Rules);
    }

    [Fact]
    public void WithoutAGuardian_NothingIsEnforced()
    {
        var rig = new Rig();
        rig.Store.Current = null;

        var report = rig.Engine.RunOnce();

        Assert.False(report.Configured);
        Assert.Empty(rig.Firewall.Rules);
    }

    [Fact]
    public void ProtectedPaths_AreNeverBlocked_EvenIfTheResolverReturnsThem()
    {
        var rig = new Rig();
        rig.Resolver.PathsByApplicationId["discord"] = new[] { @"C:\Windows\System32\svchost.exe", @"D:\x\MsMpEng.exe", DiscordExe };

        rig.Engine.RunOnce();

        var rule = Assert.Single(rig.Firewall.Rules);
        Assert.Equal(DiscordExe, rule.ProgramPath);
    }

    [Fact]
    public void FailedRemoval_DoesNotStackADuplicateRule()
    {
        var rig = new Rig();
        rig.Engine.RunOnce();
        var stuck = rig.Firewall.Rules.First(r => r.ProgramPath == DiscordExe);
        rig.Firewall.Rules[rig.Firewall.Rules.IndexOf(stuck)] = stuck with { Enabled = false }; // drifted
        rig.Firewall.FailRemoveFor.Add(stuck.Name);

        var report = rig.Engine.RunOnce();

        Assert.Equal(2, rig.Firewall.Rules.Count);
        Assert.Contains(report.Problems, p => p.Contains(stuck.Name));
    }

    [Fact]
    public void KnownToolFindings_AreReportedOnce_AndAgainAfterTheyGoAway()
    {
        var rig = new Rig();
        rig.Inventory.Inventory = new RuntimeInventory(new[] { "goodbyedpi" }, Array.Empty<string>(), Array.Empty<string>());

        var first = rig.Engine.RunOnce();
        var second = rig.Engine.RunOnce();

        Assert.Equal(1, first.NewFindingCount);
        Assert.Equal(0, second.NewFindingCount);
        Assert.Single(second.Findings);
        Assert.Single(rig.Sink.Reported);

        rig.Inventory.Inventory = new RuntimeInventory(Array.Empty<string>(), Array.Empty<string>(), Array.Empty<string>());
        rig.Engine.RunOnce();
        rig.Inventory.Inventory = new RuntimeInventory(new[] { "goodbyedpi" }, Array.Empty<string>(), Array.Empty<string>());
        rig.Engine.RunOnce();

        Assert.Equal(2, rig.Sink.Reported.Count);
    }

    [Fact]
    public void NetworkChangesAgainstTheBaseline_AreReported()
    {
        var rig = new Rig();
        rig.Store.Current = rig.Store.Current! with { Baseline = TestData.Snapshot() };
        rig.Inspector.Snapshot = TestData.Snapshot(proxies: new[] { new ProxyInfo("machine", true, "proxy.example:3128", null) });

        var report = rig.Engine.RunOnce();

        Assert.Contains(report.Findings, f => f.Code == "PROXY_CONFIGURED");
    }

    [Fact]
    public void WithoutABaseline_NetworkComparisonIsSkipped_ButToolDetectionStillRuns()
    {
        var rig = new Rig();
        rig.Inspector.Snapshot = TestData.Snapshot(proxies: new[] { new ProxyInfo("machine", true, "proxy.example:3128", null) });
        rig.Inventory.Inventory = new RuntimeInventory(new[] { "openvpn" }, Array.Empty<string>(), Array.Empty<string>());

        var report = rig.Engine.RunOnce();

        Assert.DoesNotContain(report.Findings, f => f.Code == "PROXY_CONFIGURED");
        Assert.Contains(report.Findings, f => f.Subject == "openvpn");
    }

    [Fact]
    public void DisabledFirewall_IsReported_OnlyWhileEnforcementIsOn()
    {
        var rig = new Rig();
        rig.Firewall.ProfilesEnabled = false;

        Assert.Contains(rig.Engine.RunOnce().Findings, f => f.Code == "FIREWALL_DISABLED");

        rig.UpdatePolicy(p => p with { EnforcementEnabled = false });
        Assert.DoesNotContain(rig.Engine.RunOnce().Findings, f => f.Code == "FIREWALL_DISABLED");
    }

    [Fact]
    public void ADetectorFailure_DoesNotStopEnforcement()
    {
        var rig = new Rig();
        var engine = new EnforcementEngine(
            rig.Store, rig.Resolver, rig.Firewall, new ThrowingInspector(), rig.Inventory, rig.Sink, TestData.Validator(), NullLogger<EnforcementEngine>.Instance);
        rig.Store.Current = rig.Store.Current! with { Baseline = TestData.Snapshot() };

        var report = engine.RunOnce();

        Assert.True(report.Enforced);
        Assert.Equal(2, rig.Firewall.Rules.Count);
    }

    [Fact]
    public void TargetingAnAdministratorProfile_IsReportedAsAWarning()
    {
        var rig = new Rig();
        rig.UpdatePolicy(p => p with { TargetProfiles = new[] { "kid" } });
        rig.Accounts.Profiles.Add(new ProfileAccount("kid", true));

        var report = rig.Engine.RunOnce();

        var finding = Assert.Single(report.Findings, f => f.Code == "TARGET_PROFILE_IS_ADMINISTRATOR");
        Assert.Equal(FindingSeverity.Warning, finding.Severity);
        Assert.Equal(2, rig.Firewall.Rules.Count); // the warning does not stop enforcement
    }

    [Fact]
    public void StandardProfile_RaisesNoAccountFinding()
    {
        var rig = new Rig();
        rig.UpdatePolicy(p => p with { TargetProfiles = new[] { "kid" } });
        rig.Accounts.Profiles.Add(new ProfileAccount("kid", false));

        Assert.DoesNotContain(rig.Engine.RunOnce().Findings, f => f.Code.StartsWith("TARGET_PROFILE"));
    }

    [Fact]
    public void AccountCheck_RunsOnlyWhileEnforcementIsOn()
    {
        var rig = new Rig(enforcementEnabled: false);
        rig.UpdatePolicy(p => p with { TargetProfiles = new[] { "kid" } });
        rig.Accounts.Profiles.Add(new ProfileAccount("kid", true));

        Assert.DoesNotContain(rig.Engine.RunOnce().Findings, f => f.Code.StartsWith("TARGET_PROFILE"));
    }

    [Fact]
    public void AccountInspectorFailure_DoesNotStopEnforcement()
    {
        var rig = new Rig();
        rig.Accounts.Throw = true;

        var report = rig.Engine.RunOnce();

        Assert.True(report.Enforced);
        Assert.Equal(2, rig.Firewall.Rules.Count);
    }

    private sealed class ThrowingInspector : Abstractions.INetworkInspector
    {
        public NetworkSnapshot Capture() => throw new InvalidOperationException("adapter enumeration failed");
    }
}

public class PrivacyBoundaryTests
{
    [Fact]
    public void CoreAssembly_HasNoNetworkingReferences()
    {
        // The product must be physically unable to upload anything: its core logic references no HTTP or socket APIs.
        var referenced = typeof(EnforcementEngine).Assembly.GetReferencedAssemblies().Select(a => a.Name).ToList();

        Assert.DoesNotContain("System.Net.Http", referenced);
        Assert.DoesNotContain("System.Net.Sockets", referenced);
        Assert.DoesNotContain("System.Net.WebClient", referenced);
        Assert.DoesNotContain("System.Net.Requests", referenced);
    }

    [Fact]
    public void TransparencyStatement_StatesTheLimits()
    {
        Assert.Contains("does not hide", TransparencyStatement.Text);
        Assert.Contains("does not upload", TransparencyStatement.Text);
        Assert.Contains("keystrokes", TransparencyStatement.Text);
    }
}
