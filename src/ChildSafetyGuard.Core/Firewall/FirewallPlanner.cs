using System.Security.Cryptography;
using System.Text;
using ChildSafetyGuard.Core.Models;

namespace ChildSafetyGuard.Core.Firewall;

/// <summary>Turns resolved applications into the exact set of firewall rules the product wants to exist.</summary>
public static class FirewallPlanner
{
    public const string GroupName = "Child Safety Guard";

    /// <summary>Every rule this product owns starts with this prefix; nothing else is ever listed, changed or removed.</summary>
    public const string NamePrefix = "ChildSafetyGuard.";

    public static IReadOnlyList<FirewallRuleSpec> BuildDesiredRules(IEnumerable<ResolvedApplication> applications)
    {
        var rules = new List<FirewallRuleSpec>();
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var resolved in applications)
        {
            foreach (var path in resolved.Paths)
            {
                var name = RuleName(resolved.Application.Id, path);
                if (!names.Add(name))
                {
                    continue;
                }

                rules.Add(new FirewallRuleSpec(
                    name,
                    $"Blocks outbound network access for {resolved.Application.DisplayName}. Managed by Child Safety Guard on behalf of the device guardian.",
                    path));
            }
        }

        return rules;
    }

    public static string RuleName(string applicationId, string path)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(path.ToLowerInvariant()));
        return $"{NamePrefix}{applicationId}.{Convert.ToHexString(hash, 0, 4).ToLowerInvariant()}";
    }
}
