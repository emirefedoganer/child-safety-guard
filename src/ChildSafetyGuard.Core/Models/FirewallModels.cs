namespace ChildSafetyGuard.Core.Models;

/// <summary>An outbound "block" rule for one program path.</summary>
public sealed record FirewallRuleSpec(string Name, string Description, string ProgramPath);

public sealed record ExistingFirewallRule(string Name, string ProgramPath, bool Enabled, bool IsBlock, bool IsOutbound);

public sealed record FirewallChangeSet(IReadOnlyList<FirewallRuleSpec> Add, IReadOnlyList<string> Remove)
{
    public bool IsEmpty => Add.Count == 0 && Remove.Count == 0;
}

public sealed record ResolvedApplication(BlockedApplication Application, IReadOnlyList<string> Paths);
