namespace ChildSafetyGuard.Core.Detection;

public enum ToolCategory
{
    /// <summary>Local packet-rewriting tools that defeat DPI-based blocking (not VPNs; the public IP does not change).</summary>
    DpiBypass,

    /// <summary>Packet capture/filter drivers. Legitimate in many products; informational only.</summary>
    PacketFilterDriver,

    VpnClient,
    ProxyOrTunnel,
}

/// <param name="ProcessNames">Process names without the .exe extension.</param>
/// <param name="ServiceNames">Windows service or driver names; '*' wildcards allowed.</param>
public sealed record KnownTool(
    string Id,
    string DisplayName,
    ToolCategory Category,
    IReadOnlyList<string> ProcessNames,
    IReadOnlyList<string> ServiceNames,
    string Note);

/// <summary>
/// Public names of well-known tools. Matching is by process, service and driver names only — no files are read,
/// no memory is inspected. A name match is a lead for a conversation, not proof.
/// </summary>
public static class KnownToolCatalog
{
    private static readonly string[] None = Array.Empty<string>();

    public static IReadOnlyList<KnownTool> Default { get; } = new[]
    {
        new KnownTool("goodbyedpi", "GoodbyeDPI", ToolCategory.DpiBypass,
            new[] { "goodbyedpi" }, new[] { "GoodbyeDPI" },
            "GoodbyeDPI rewrites packets locally using the WinDivert driver to get around DPI-based blocking. It is not a VPN: the public IP address does not change, so it cannot be found by comparing IP addresses."),
        new KnownTool("zapret", "zapret (winws)", ToolCategory.DpiBypass,
            new[] { "winws" }, None,
            "zapret is a local DPI-circumvention tool that, like GoodbyeDPI, rewrites packets on the device."),
        new KnownTool("byedpi", "ByeDPI", ToolCategory.DpiBypass,
            new[] { "ciadpi" }, None,
            "ByeDPI is a local DPI-circumvention proxy."),
        new KnownTool("powertunnel", "PowerTunnel", ToolCategory.DpiBypass,
            new[] { "powertunnel" }, None,
            "PowerTunnel is a local proxy used to get around DPI-based blocking."),
        new KnownTool("windivert", "WinDivert packet driver", ToolCategory.PacketFilterDriver,
            None, new[] { "WinDivert*" },
            "WinDivert is a legitimate packet capture/modification driver used by several firewalls, network tools and circumvention tools. Its presence alone is not evidence of circumvention."),
        new KnownTool("wireguard", "WireGuard", ToolCategory.VpnClient,
            new[] { "wireguard" }, new[] { "WireGuardManager", "WireGuardTunnel$*" },
            "WireGuard is a VPN client that routes traffic through a remote server."),
        new KnownTool("openvpn", "OpenVPN", ToolCategory.VpnClient,
            new[] { "openvpn", "openvpn-gui" }, new[] { "OpenVPNService", "OpenVPNServiceInteractive", "ovpnagent" },
            "OpenVPN is a VPN client that routes traffic through a remote server."),
        new KnownTool("nordvpn", "NordVPN", ToolCategory.VpnClient,
            new[] { "nordvpn", "nordvpn-service" }, new[] { "nordvpn-service" },
            "NordVPN is a commercial VPN client."),
        new KnownTool("protonvpn", "Proton VPN", ToolCategory.VpnClient,
            new[] { "protonvpn" }, new[] { "ProtonVPN*" },
            "Proton VPN is a commercial VPN client."),
        new KnownTool("expressvpn", "ExpressVPN", ToolCategory.VpnClient,
            new[] { "expressvpn", "expressvpnd" }, new[] { "ExpressVpnService" },
            "ExpressVPN is a commercial VPN client."),
        new KnownTool("windscribe", "Windscribe", ToolCategory.VpnClient,
            new[] { "windscribe" }, new[] { "WindscribeService" },
            "Windscribe is a commercial VPN client."),
        new KnownTool("cloudflare-warp", "Cloudflare WARP", ToolCategory.VpnClient,
            new[] { "warp-svc", "warp-taskbar" }, new[] { "CloudflareWARP" },
            "Cloudflare WARP routes traffic through Cloudflare's network. It is also used for ordinary privacy reasons."),
        new KnownTool("psiphon", "Psiphon", ToolCategory.ProxyOrTunnel,
            new[] { "psiphon3" }, None,
            "Psiphon is a circumvention tool that tunnels traffic through remote servers."),
        new KnownTool("tor", "Tor", ToolCategory.ProxyOrTunnel,
            new[] { "tor" }, None,
            "The Tor daemon routes traffic through the Tor network; Tor Browser starts it."),
        new KnownTool("v2ray-clash", "V2Ray / Xray / Clash family", ToolCategory.ProxyOrTunnel,
            new[] { "v2rayn", "v2ray", "xray", "clash", "clash-verge" }, None,
            "These are proxy/tunnel clients commonly used to route traffic through remote servers."),
    };
}
