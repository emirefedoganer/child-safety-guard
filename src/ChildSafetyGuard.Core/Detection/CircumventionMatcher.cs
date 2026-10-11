using ChildSafetyGuard.Core.Models;
using ChildSafetyGuard.Core.Util;

namespace ChildSafetyGuard.Core.Detection;

/// <summary>
/// Matches an inventory of process, service and driver names against the known-tool catalog.
/// Produces explainable findings and never takes action on its own.
/// </summary>
public static class CircumventionMatcher
{
    public static IReadOnlyList<Finding> Match(
        RuntimeInventory inventory,
        IEnumerable<KnownTool> catalog,
        IEnumerable<string> extraProcessNames)
    {
        var findings = new List<Finding>();
        var running = new HashSet<string>(inventory.ProcessNames.Select(NormalizeProcess), StringComparer.OrdinalIgnoreCase);

        foreach (var tool in catalog)
        {
            var processHits = tool.ProcessNames
                .Select(NormalizeProcess)
                .Where(p => running.Contains(p))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            if (processHits.Count > 0)
            {
                findings.Add(new Finding(
                    "TOOL_PROCESS_RUNNING",
                    SeverityFor(tool.Category),
                    $"{tool.DisplayName} appears to be running",
                    Explain(tool),
                    tool.Id,
                    processHits.Select(p => $"Process name: {p}").ToList()));
            }

            var installed = MatchNames(inventory.ServiceNames, tool.ServiceNames).Select(n => $"Service: {n}")
                .Concat(MatchNames(inventory.DriverNames, tool.ServiceNames).Select(n => $"Driver: {n}"))
                .ToList();
            if (installed.Count > 0)
            {
                findings.Add(new Finding(
                    "TOOL_SERVICE_INSTALLED",
                    SeverityFor(tool.Category),
                    $"{tool.DisplayName} has a service or driver installed",
                    Explain(tool),
                    tool.Id,
                    installed));
            }
        }

        foreach (var extra in extraProcessNames.Select(NormalizeProcess).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (running.Contains(extra))
            {
                findings.Add(new Finding(
                    "WATCHED_PROCESS_RUNNING",
                    FindingSeverity.Notice,
                    $"Guardian-watched process '{extra}' is running",
                    "This process name is on the watch list the guardian configured. Only the process name was checked.",
                    "watched:" + extra,
                    new[] { $"Process name: {extra}" }));
            }
        }

        return findings;
    }

    internal static string NormalizeProcess(string name)
    {
        var trimmed = name.Trim();
        return trimmed.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? trimmed[..^4] : trimmed;
    }

    private static List<string> MatchNames(IEnumerable<string> actual, IReadOnlyList<string> patterns) =>
        actual
            .Where(a => patterns.Any(p => GlobMatcher.IsMatch(p, a)))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

    private static FindingSeverity SeverityFor(ToolCategory category) =>
        category == ToolCategory.DpiBypass ? FindingSeverity.Warning : FindingSeverity.Notice;

    private static string Explain(KnownTool tool) =>
        tool.Note + " This finding is based only on process, service or driver names; no files were read. " +
        "Treat it as a reason to talk with the device user, not as proof of anything.";
}
