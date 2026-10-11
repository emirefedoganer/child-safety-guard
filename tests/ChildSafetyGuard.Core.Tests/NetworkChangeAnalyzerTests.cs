using ChildSafetyGuard.Core.Models;
using ChildSafetyGuard.Core.Network;

namespace ChildSafetyGuard.Core.Tests;

public class NetworkChangeAnalyzerTests
{
    private static IReadOnlyList<Finding> Analyze(NetworkSnapshot baseline, NetworkSnapshot current) =>
        NetworkChangeAnalyzer.Analyze(baseline, current);

    [Fact]
    public void UnchangedNetwork_HasNoFindings()
    {
        var snapshot = TestData.Snapshot();

        Assert.Empty(Analyze(snapshot, snapshot));
    }

    [Fact]
    public void NewWintunAdapter_IsAWarning_ThatExplainsItIsNotProof()
    {
        var baseline = TestData.Snapshot();
        var current = TestData.Snapshot(new[]
        {
            TestData.Adapter(),
            TestData.Adapter("{tun}", "WireGuard Tunnel", "Wintun Userspace Tunnel", AdapterKind.Other),
        });

        var finding = Assert.Single(Analyze(baseline, current));

        Assert.Equal("NEW_TUNNEL_ADAPTER", finding.Code);
        Assert.Equal(FindingSeverity.Warning, finding.Severity);
        Assert.Contains("does not prove", finding.Explanation);
        Assert.Contains(finding.Evidence, e => e.Contains("Wintun"));
    }

    [Fact]
    public void NewUsbEthernetAdapter_IsOnlyInformational()
    {
        var current = TestData.Snapshot(new[]
        {
            TestData.Adapter(),
            TestData.Adapter("{usb}", "Ethernet 2", "Realtek USB GbE Family Controller", AdapterKind.Ethernet),
        });

        var finding = Assert.Single(Analyze(TestData.Snapshot(), current));

        Assert.Equal(FindingSeverity.Info, finding.Severity);
    }

    [Theory]
    [InlineData("Teredo Tunneling Pseudo-Interface")]
    [InlineData("Microsoft 6to4 Adapter")]
    [InlineData("Hyper-V Virtual Ethernet Adapter")]
    public void BuiltInWindowsAdapters_AreNotTreatedAsVpns(string description)
    {
        var current = TestData.Snapshot(new[]
        {
            TestData.Adapter(),
            TestData.Adapter("{builtin}", "Local Area Connection*", description, AdapterKind.Tunnel),
        });

        var finding = Assert.Single(Analyze(TestData.Snapshot(), current));

        Assert.Equal(FindingSeverity.Info, finding.Severity);
    }

    [Fact]
    public void ChangedDnsServers_AreANotice_WithBeforeAndAfter()
    {
        var current = TestData.Snapshot(new[] { TestData.Adapter(dns: new[] { "8.8.8.8" }) });

        var finding = Assert.Single(Analyze(TestData.Snapshot(), current));

        Assert.Equal("DNS_CHANGED", finding.Code);
        Assert.Equal(FindingSeverity.Notice, finding.Severity);
        Assert.Contains(finding.Evidence, e => e.Contains("192.168.1.1"));
        Assert.Contains(finding.Evidence, e => e.Contains("8.8.8.8"));
    }

    [Fact]
    public void DnsOrder_DoesNotMatter()
    {
        var baseline = TestData.Snapshot(new[] { TestData.Adapter(dns: new[] { "1.1.1.1", "9.9.9.9" }) });
        var current = TestData.Snapshot(new[] { TestData.Adapter(dns: new[] { "9.9.9.9", "1.1.1.1" }) });

        Assert.Empty(Analyze(baseline, current));
    }

    [Fact]
    public void AdapterThatIsDownNow_DoesNotRaiseDnsOrGatewayNoise()
    {
        var current = TestData.Snapshot(new[] { TestData.Adapter(up: false, dns: Array.Empty<string>(), gateways: Array.Empty<string>()) });

        Assert.Empty(Analyze(TestData.Snapshot(), current));
    }

    [Fact]
    public void ChangedGateway_IsANotice()
    {
        var current = TestData.Snapshot(new[] { TestData.Adapter(gateways: new[] { "10.0.0.1" }) });

        Assert.Equal("GATEWAY_CHANGED", Assert.Single(Analyze(TestData.Snapshot(), current)).Code);
    }

    [Fact]
    public void VpnAdapterThatWasDownAndComesUp_IsAWarning()
    {
        var vpn = TestData.Adapter("{tun}", "OpenVPN", "TAP-Windows Adapter V9", AdapterKind.Ethernet);
        var baseline = TestData.Snapshot(new[] { TestData.Adapter(), vpn with { IsUp = false } });
        var current = TestData.Snapshot(new[] { TestData.Adapter(), vpn with { IsUp = true } });

        var finding = Assert.Single(Analyze(baseline, current));

        Assert.Equal("TUNNEL_ADAPTER_ACTIVATED", finding.Code);
        Assert.Equal(FindingSeverity.Warning, finding.Severity);
    }

    [Fact]
    public void NewProxy_IsAWarning_ButAnUnchangedBaselineProxyIsNot()
    {
        var proxy = new ProxyInfo("user:S-1-5-21-1", true, "proxy.example:8080", null);

        var added = Assert.Single(Analyze(TestData.Snapshot(), TestData.Snapshot(proxies: new[] { proxy })));
        Assert.Equal("PROXY_CONFIGURED", added.Code);

        var withProxyBaseline = TestData.Snapshot(proxies: new[] { proxy });
        Assert.Empty(Analyze(withProxyBaseline, withProxyBaseline));
    }

    [Fact]
    public void InactiveProxyEntries_AreIgnored()
    {
        var inactive = new ProxyInfo("machine", false, "left-over:8080", null);

        Assert.Empty(Analyze(TestData.Snapshot(), TestData.Snapshot(proxies: new[] { inactive })));
    }
}
