using ChildSafetyGuard.Core.Firewall;
using ChildSafetyGuard.Core.Models;

namespace ChildSafetyGuard.Core.Tests;

public class FirewallPlannerTests
{
    private static readonly BlockedApplication Discord = DefaultApplications.All[0];

    [Fact]
    public void BuildsOneOutboundRulePerPath_WithStableOwnedNames()
    {
        var resolved = new[]
        {
            new ResolvedApplication(Discord, new[] { @"C:\Users\kid\AppData\Local\Discord\Update.exe", @"C:\Users\kid\AppData\Local\Discord\app-1\Discord.exe" }),
        };

        var rules = FirewallPlanner.BuildDesiredRules(resolved);

        Assert.Equal(2, rules.Count);
        Assert.All(rules, r => Assert.StartsWith(FirewallPlanner.NamePrefix, r.Name));
        Assert.Equal(rules.Select(r => r.Name), FirewallPlanner.BuildDesiredRules(resolved).Select(r => r.Name)); // deterministic
    }

    [Fact]
    public void RuleNames_AreCaseInsensitiveOnPath_AndDeduplicated()
    {
        var resolved = new[] { new ResolvedApplication(Discord, new[] { @"C:\A\Discord.exe", @"c:\a\discord.exe" }) };

        Assert.Single(FirewallPlanner.BuildDesiredRules(resolved));
    }
}

public class FirewallReconcilerTests
{
    private static FirewallRuleSpec Spec(string path) =>
        new(TestData.Rule("discord", path), "desc", path);

    private static ExistingFirewallRule Existing(FirewallRuleSpec spec, bool enabled = true, bool block = true, bool outbound = true) =>
        new(spec.Name, spec.ProgramPath, enabled, block, outbound);

    [Fact]
    public void EmptyExisting_AddsEverything()
    {
        var desired = new[] { Spec(@"C:\a.exe"), Spec(@"C:\b.exe") };

        var changes = FirewallReconciler.Plan(desired, Array.Empty<ExistingFirewallRule>());

        Assert.Equal(2, changes.Add.Count);
        Assert.Empty(changes.Remove);
    }

    [Fact]
    public void MatchingRules_ProduceNoChanges()
    {
        var desired = new[] { Spec(@"C:\a.exe") };

        Assert.True(FirewallReconciler.Plan(desired, desired.Select(s => Existing(s)).ToList()).IsEmpty);
    }

    [Fact]
    public void StaleRules_AreRemoved()
    {
        var stale = Spec(@"C:\old.exe");

        var changes = FirewallReconciler.Plan(Array.Empty<FirewallRuleSpec>(), new[] { Existing(stale) });

        Assert.Equal(new[] { stale.Name }, changes.Remove);
        Assert.Empty(changes.Add);
    }

    [Theory]
    [InlineData(false, true, true)]   // disabled by someone
    [InlineData(true, false, true)]   // flipped to allow
    [InlineData(true, true, false)]   // flipped to inbound
    public void DriftedRules_AreReplaced(bool enabled, bool block, bool outbound)
    {
        var spec = Spec(@"C:\a.exe");

        var changes = FirewallReconciler.Plan(new[] { spec }, new[] { Existing(spec, enabled, block, outbound) });

        Assert.Equal(new[] { spec.Name }, changes.Remove);
        Assert.Equal(new[] { spec }, changes.Add);
    }

    [Fact]
    public void DuplicateRules_AreReplaced()
    {
        var spec = Spec(@"C:\a.exe");

        var changes = FirewallReconciler.Plan(new[] { spec }, new[] { Existing(spec), Existing(spec) });

        Assert.Single(changes.Remove);
        Assert.Single(changes.Add);
    }
}
