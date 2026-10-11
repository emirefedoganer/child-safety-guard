using System.Text.Json.Serialization;

namespace ChildSafetyGuard.Core.Models;

/// <summary>
/// A deliberately small description of the device's network configuration.
/// It contains configuration only — never traffic, URLs, or browsing content.
/// </summary>
public sealed record NetworkSnapshot(
    DateTimeOffset CapturedAtUtc,
    IReadOnlyList<AdapterInfo> Adapters,
    IReadOnlyList<ProxyInfo> Proxies);

public sealed record AdapterInfo(
    string Id,
    string Name,
    string Description,
    AdapterKind Kind,
    bool IsUp,
    IReadOnlyList<string> Addresses,
    IReadOnlyList<string> Gateways,
    IReadOnlyList<string> DnsServers);

/// <param name="Scope">"machine" or "user:&lt;SID&gt;".</param>
public sealed record ProxyInfo(string Scope, bool Enabled, string? Server, string? AutoConfigUrl);

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum AdapterKind
{
    Ethernet,
    Wireless,
    Tunnel,
    Ppp,
    Other,
}

/// <summary>Names of running processes, installed services and driver services. Names only.</summary>
public sealed record RuntimeInventory(
    IReadOnlyCollection<string> ProcessNames,
    IReadOnlyCollection<string> ServiceNames,
    IReadOnlyCollection<string> DriverNames);
