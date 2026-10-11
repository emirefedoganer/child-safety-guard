using ChildSafetyGuard.Core.Detection;
using ChildSafetyGuard.Core.Models;

namespace ChildSafetyGuard.Core.Tests;

public class CircumventionMatcherTests
{
    private static RuntimeInventory Inventory(string[]? processes = null, string[]? services = null, string[]? drivers = null) =>
        new(processes ?? Array.Empty<string>(), services ?? Array.Empty<string>(), drivers ?? Array.Empty<string>());

    private static IReadOnlyList<Finding> Match(RuntimeInventory inventory, params string[] extra) =>
        CircumventionMatcher.Match(inventory, KnownToolCatalog.Default, extra);

    [Fact]
    public void QuietMachine_HasNoFindings() =>
        Assert.Empty(Match(Inventory(new[] { "explorer", "chrome", "Code" })));

    [Fact]
    public void RunningGoodbyeDpi_IsAWarning_ThatExplainsWhyIpComparisonCannotSeeIt()
    {
        var finding = Assert.Single(Match(Inventory(new[] { "GoodbyeDPI.exe", "explorer" })));

        Assert.Equal("TOOL_PROCESS_RUNNING", finding.Code);
        Assert.Equal(FindingSeverity.Warning, finding.Severity);
        Assert.Equal("goodbyedpi", finding.Subject);
        Assert.Contains("not a VPN", finding.Explanation);
        Assert.Contains("no files were read", finding.Explanation);
    }

    [Fact]
    public void WinDivertDriver_IsOnlyANotice_BecauseItIsALegitimateLibrary()
    {
        var finding = Assert.Single(Match(Inventory(drivers: new[] { "WinDivert1.4" })));

        Assert.Equal("TOOL_SERVICE_INSTALLED", finding.Code);
        Assert.Equal(FindingSeverity.Notice, finding.Severity);
        Assert.Contains("not evidence", finding.Explanation);
        Assert.Contains(finding.Evidence, e => e == "Driver: WinDivert1.4");
    }

    [Fact]
    public void GoodbyeDpiService_IsWarning_AndNamedInEvidence()
    {
        var finding = Assert.Single(Match(Inventory(services: new[] { "GoodbyeDPI" })));

        Assert.Equal(FindingSeverity.Warning, finding.Severity);
        Assert.Contains(finding.Evidence, e => e == "Service: GoodbyeDPI");
    }

    [Fact]
    public void ProcessWithSimilarNameIsNotMatched() =>
        Assert.Empty(Match(Inventory(new[] { "tortoisegit", "tormenta", "xrayviewer" })));

    [Fact]
    public void GuardianWatchedProcess_IsReported()
    {
        var finding = Assert.Single(Match(Inventory(new[] { "mygame.exe" }), "MyGame"));

        Assert.Equal("WATCHED_PROCESS_RUNNING", finding.Code);
    }

    [Fact]
    public void FindingKeys_AreStableAcrossRuns()
    {
        var first = Assert.Single(Match(Inventory(new[] { "goodbyedpi" })));
        var second = Assert.Single(Match(Inventory(new[] { "goodbyedpi" })));

        Assert.Equal(first.Key, second.Key);
    }
}
