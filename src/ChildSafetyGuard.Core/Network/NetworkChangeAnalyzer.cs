using ChildSafetyGuard.Core.Models;

namespace ChildSafetyGuard.Core.Network;

/// <summary>
/// Compares the current network configuration with the baseline recorded during guardian setup.
/// Every finding explains what changed and what it does not prove: a changed DNS server is just as
/// likely a different Wi-Fi network as a circumvention tool.
/// </summary>
/// <remarks>
/// This cannot see packet-rewriting tools such as GoodbyeDPI: they change neither the adapters nor the
/// public IP address. Those are handled by <see cref="Detection.CircumventionMatcher"/>.
/// </remarks>
public static class NetworkChangeAnalyzer
{
    private static readonly string[] VpnSignatures =
    {
        "TAP-Windows", "TAP-NordVPN", "Wintun", "WireGuard", "OpenVPN", "NordLynx", "Windscribe", "ProtonVPN",
        "ExpressVPN", "Mullvad", "Cloudflare WARP", "Surfshark", "SoftEther", "TunnelBear", "Hamachi",
        "ZeroTier", "Tailscale", "AnyConnect", "FortiClient", "Fortinet",
    };

    // Adapters Windows itself creates; their appearance is routine.
    private static readonly string[] BuiltInSignatures =
    {
        "Teredo", "ISATAP", "6to4", "IP-HTTPS", "Wi-Fi Direct", "Hyper-V", "vEthernet", "WAN Miniport", "Bluetooth",
    };

    public static IReadOnlyList<Finding> Analyze(NetworkSnapshot baseline, NetworkSnapshot current)
    {
        var findings = new List<Finding>();
        var before = baseline.Adapters.GroupBy(a => a.Id).ToDictionary(g => g.Key, g => g.First());

        foreach (var adapter in current.Adapters)
        {
            if (!before.TryGetValue(adapter.Id, out var previous))
            {
                findings.Add(DescribeNewAdapter(adapter));
                continue;
            }

            AnalyzeExisting(previous, adapter, findings);
        }

        AnalyzeProxies(baseline.Proxies, current.Proxies, findings);
        return findings;
    }

    private static Finding DescribeNewAdapter(AdapterInfo adapter)
    {
        var evidence = new List<string>
        {
            $"Adapter: {adapter.Name}",
            $"Description: {adapter.Description}",
            $"Type: {adapter.Kind}",
            $"State: {(adapter.IsUp ? "up" : "down")}",
        };

        if (IsTunnelLike(adapter))
        {
            return new Finding(
                "NEW_TUNNEL_ADAPTER",
                FindingSeverity.Warning,
                "A new tunnel or VPN-style network adapter appeared",
                "This adapter was not present when the baseline was recorded and looks like a tunnel/VPN virtual adapter " +
                "(by adapter type or a well-known driver name). VPN clients, some school or work tools and remote-access " +
                "software create such adapters, so this is a signal to review — it does not prove circumvention.",
                adapter.Id,
                evidence);
        }

        return new Finding(
            "NEW_ADAPTER",
            FindingSeverity.Info,
            "A new network adapter appeared",
            "This adapter was not present when the baseline was recorded. Plugging in a USB network adapter, enabling a " +
            "virtual machine or a phone hotspot commonly causes this.",
            adapter.Id,
            evidence);
    }

    private static void AnalyzeExisting(AdapterInfo previous, AdapterInfo current, List<Finding> findings)
    {
        if (previous.IsUp && current.IsUp)
        {
            if (!SameSet(previous.DnsServers, current.DnsServers))
            {
                findings.Add(new Finding(
                    "DNS_CHANGED",
                    FindingSeverity.Notice,
                    "DNS servers changed on an adapter",
                    "The DNS servers differ from the baseline. This is expected after joining a different Wi-Fi network or " +
                    "after a router change; it can also happen when a VPN, a 'secure DNS' tool or a manual DNS change is used.",
                    current.Id,
                    new[]
                    {
                        $"Adapter: {current.Name}",
                        $"Baseline: {Join(previous.DnsServers)}",
                        $"Now: {Join(current.DnsServers)}",
                    }));
            }

            if (!SameSet(previous.Gateways, current.Gateways))
            {
                findings.Add(new Finding(
                    "GATEWAY_CHANGED",
                    FindingSeverity.Notice,
                    "Default gateway changed on an adapter",
                    "The default gateway differs from the baseline. Changing networks does this routinely; routing traffic " +
                    "through a tunnel can too.",
                    current.Id,
                    new[]
                    {
                        $"Adapter: {current.Name}",
                        $"Baseline: {Join(previous.Gateways)}",
                        $"Now: {Join(current.Gateways)}",
                    }));
            }
        }

        if (!previous.IsUp && current.IsUp && IsTunnelLike(current))
        {
            findings.Add(new Finding(
                "TUNNEL_ADAPTER_ACTIVATED",
                FindingSeverity.Warning,
                "A tunnel or VPN-style adapter became active",
                "This adapter existed in the baseline but was down; it is now up. A VPN or tunnel client was probably connected.",
                current.Id,
                new[] { $"Adapter: {current.Name}", $"Description: {current.Description}", $"Type: {current.Kind}" }));
        }
    }

    private static void AnalyzeProxies(IReadOnlyList<ProxyInfo> baseline, IReadOnlyList<ProxyInfo> current, List<Finding> findings)
    {
        foreach (var proxy in current)
        {
            var active = proxy.Enabled || !string.IsNullOrWhiteSpace(proxy.AutoConfigUrl);
            if (!active)
            {
                continue;
            }

            var previous = baseline.FirstOrDefault(p => p.Scope == proxy.Scope);
            var unchanged = previous is not null &&
                            previous.Enabled == proxy.Enabled &&
                            previous.Server == proxy.Server &&
                            previous.AutoConfigUrl == proxy.AutoConfigUrl;
            if (unchanged)
            {
                continue;
            }

            findings.Add(new Finding(
                "PROXY_CONFIGURED",
                FindingSeverity.Warning,
                "A system proxy or proxy auto-config script is set",
                "A proxy that was not part of the baseline is configured. Proxies are used by some schools, workplaces and " +
                "privacy tools; they can also route traffic around network-level restrictions.",
                proxy.Scope,
                new[]
                {
                    $"Scope: {proxy.Scope}",
                    $"Proxy enabled: {proxy.Enabled}",
                    $"Server: {proxy.Server ?? "(none)"}",
                    $"Auto-config URL: {proxy.AutoConfigUrl ?? "(none)"}",
                }));
        }
    }

    private static bool IsTunnelLike(AdapterInfo adapter)
    {
        if (ContainsAny(adapter.Description, BuiltInSignatures) || ContainsAny(adapter.Name, BuiltInSignatures))
        {
            return false;
        }

        return ContainsAny(adapter.Description, VpnSignatures) ||
               ContainsAny(adapter.Name, VpnSignatures) ||
               adapter.Kind is AdapterKind.Tunnel or AdapterKind.Ppp;
    }

    private static bool ContainsAny(string? text, string[] needles) =>
        !string.IsNullOrEmpty(text) && needles.Any(n => text.Contains(n, StringComparison.OrdinalIgnoreCase));

    private static bool SameSet(IReadOnlyList<string> a, IReadOnlyList<string> b) =>
        new HashSet<string>(a, StringComparer.OrdinalIgnoreCase).SetEquals(b);

    private static string Join(IReadOnlyList<string> values) => values.Count == 0 ? "(none)" : string.Join(", ", values);
}
