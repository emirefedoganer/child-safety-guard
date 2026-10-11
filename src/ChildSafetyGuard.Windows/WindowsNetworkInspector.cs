using System.Net;
using System.Net.NetworkInformation;
using ChildSafetyGuard.Core.Abstractions;
using ChildSafetyGuard.Core.Models;
using Microsoft.Extensions.Logging;

namespace ChildSafetyGuard.Windows;

/// <summary>
/// Describes the network configuration using documented .NET / Windows APIs (System.Net.NetworkInformation, which wraps
/// the IP Helper API, plus the Internet Settings registry values). It makes no network requests: in particular it does
/// not look up the public IP address, because that would send data off the device and cannot detect local DPI tools.
/// </summary>
public sealed class WindowsNetworkInspector : INetworkInspector
{
    private readonly TimeProvider _time;
    private readonly ILogger<WindowsNetworkInspector> _logger;

    public WindowsNetworkInspector(TimeProvider time, ILogger<WindowsNetworkInspector> logger)
    {
        _time = time;
        _logger = logger;
    }

    public NetworkSnapshot Capture()
    {
        var adapters = new List<AdapterInfo>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback)
            {
                continue;
            }

            try
            {
                adapters.Add(Describe(nic));
            }
            catch (Exception ex) when (ex is NetworkInformationException or PlatformNotSupportedException)
            {
                _logger.LogDebug(ex, "Skipping an adapter that could not be inspected.");
            }
        }

        return new NetworkSnapshot(
            _time.GetUtcNow(),
            adapters.OrderBy(a => a.Id, StringComparer.Ordinal).ToList(),
            ProxySettingsReader.Read());
    }

    private static AdapterInfo Describe(NetworkInterface nic)
    {
        var properties = nic.GetIPProperties();

        var addresses = properties.UnicastAddresses
            .Select(u => u.Address)
            .Where(a => !a.IsIPv6LinkLocal && !a.IsIPv6Multicast)
            .Select(a => a.ToString())
            .OrderBy(a => a, StringComparer.Ordinal)
            .ToList();

        var gateways = properties.GatewayAddresses
            .Select(g => g.Address)
            .Where(a => !IPAddress.Any.Equals(a) && !IPAddress.IPv6Any.Equals(a))
            .Select(a => a.ToString())
            .OrderBy(a => a, StringComparer.Ordinal)
            .ToList();

        // Windows lists three well-known site-local IPv6 resolver addresses when none is configured; ignore them.
        var dns = properties.DnsAddresses
            .Where(a => !a.IsIPv6SiteLocal && !a.IsIPv6LinkLocal)
            .Select(a => a.ToString())
            .OrderBy(a => a, StringComparer.Ordinal)
            .ToList();

        return new AdapterInfo(
            nic.Id,
            nic.Name,
            nic.Description,
            MapKind(nic.NetworkInterfaceType),
            nic.OperationalStatus == OperationalStatus.Up,
            addresses,
            gateways,
            dns);
    }

    private static AdapterKind MapKind(NetworkInterfaceType type) => type switch
    {
        NetworkInterfaceType.Ethernet or NetworkInterfaceType.GigabitEthernet or NetworkInterfaceType.FastEthernetT
            or NetworkInterfaceType.FastEthernetFx or NetworkInterfaceType.Ethernet3Megabit => AdapterKind.Ethernet,
        NetworkInterfaceType.Wireless80211 => AdapterKind.Wireless,
        NetworkInterfaceType.Tunnel => AdapterKind.Tunnel,
        NetworkInterfaceType.Ppp => AdapterKind.Ppp,
        _ => AdapterKind.Other,
    };
}
