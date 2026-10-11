using ChildSafetyGuard.Core.Models;

namespace ChildSafetyGuard.Core.Firewall;

/// <summary>Pure diff between desired and existing managed rules. Idempotent: planning twice yields an empty change set.</summary>
public static class FirewallReconciler
{
    public static FirewallChangeSet Plan(
        IReadOnlyList<FirewallRuleSpec> desired,
        IReadOnlyList<ExistingFirewallRule> existing)
    {
        var existingByName = existing
            .GroupBy(r => r.Name, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.ToList(), StringComparer.OrdinalIgnoreCase);
        var desiredNames = new HashSet<string>(desired.Select(d => d.Name), StringComparer.OrdinalIgnoreCase);

        var remove = new List<string>();
        var add = new List<FirewallRuleSpec>();

        // Rules we own that are no longer wanted.
        foreach (var name in existingByName.Keys.Where(n => !desiredNames.Contains(n)).OrderBy(n => n, StringComparer.Ordinal))
        {
            remove.Add(name);
        }

        // Wanted rules that are missing, drifted (path/enabled/action/direction changed) or duplicated.
        foreach (var spec in desired)
        {
            if (!existingByName.TryGetValue(spec.Name, out var found))
            {
                add.Add(spec);
                continue;
            }

            var healthy = found.Count == 1 && Matches(spec, found[0]);
            if (!healthy)
            {
                remove.Add(spec.Name);
                add.Add(spec);
            }
        }

        return new FirewallChangeSet(add, remove);
    }

    private static bool Matches(FirewallRuleSpec spec, ExistingFirewallRule rule) =>
        rule.Enabled &&
        rule.IsBlock &&
        rule.IsOutbound &&
        string.Equals(spec.ProgramPath, rule.ProgramPath, StringComparison.OrdinalIgnoreCase);
}
