using ChildSafetyGuard.Core.Models;

namespace ChildSafetyGuard.Core.Enforcement;

/// <param name="Configured">A guardian exists, so there is a policy to enforce.</param>
/// <param name="Enforced">The policy was valid and firewall reconciliation ran.</param>
/// <param name="Findings">All current findings (not only new ones).</param>
/// <param name="NewFindingCount">How many findings were newly reported to the sink during this run.</param>
public sealed record EnforcementReport(
    bool Configured,
    bool Enforced,
    int RulesAdded,
    int RulesRemoved,
    IReadOnlyList<string> Problems,
    IReadOnlyList<Finding> Findings,
    int NewFindingCount);
