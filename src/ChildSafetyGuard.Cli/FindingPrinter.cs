using ChildSafetyGuard.Core.Models;

namespace ChildSafetyGuard.Cli;

internal static class FindingPrinter
{
    public static void Print(IReadOnlyList<Finding> findings)
    {
        if (findings.Count == 0)
        {
            ConsoleIO.Info("No findings.");
            return;
        }

        foreach (var finding in findings.OrderByDescending(f => f.Severity))
        {
            Console.WriteLine($"[{finding.Severity.ToString().ToUpperInvariant()}] {finding.Title}  ({finding.Code})");
            Console.WriteLine($"    {finding.Explanation}");
            foreach (var line in finding.Evidence)
            {
                Console.WriteLine($"    - {line}");
            }

            Console.WriteLine();
        }
    }
}
