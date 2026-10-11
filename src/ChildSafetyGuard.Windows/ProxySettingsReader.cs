using System.Text.RegularExpressions;
using ChildSafetyGuard.Core.Models;
using Microsoft.Win32;

namespace ChildSafetyGuard.Windows;

/// <summary>
/// Reads the documented Internet Settings proxy values (ProxyEnable, ProxyServer, AutoConfigURL) for the machine and for
/// each user hive that is currently loaded. Reads settings only — never traffic.
/// </summary>
internal static class ProxySettingsReader
{
    private const string SettingsPath = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    public static IReadOnlyList<ProxyInfo> Read()
    {
        var result = new List<ProxyInfo>();
        TryRead(result, "machine", Registry.LocalMachine, SettingsPath);

        foreach (var sid in Registry.Users.GetSubKeyNames())
        {
            var isUser = sid.StartsWith("S-1-5-21-", StringComparison.Ordinal) || sid.StartsWith("S-1-12-1-", StringComparison.Ordinal);
            if (!isUser || sid.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            TryRead(result, "user:" + sid, Registry.Users, sid + "\\" + SettingsPath);
        }

        return result.OrderBy(p => p.Scope, StringComparer.Ordinal).ToList();
    }

    private static void TryRead(List<ProxyInfo> into, string scope, RegistryKey hive, string path)
    {
        try
        {
            using var key = hive.OpenSubKey(path);
            if (key is null)
            {
                return;
            }

            var enabled = key.GetValue("ProxyEnable") is int value && value != 0;
            var server = Sanitize(key.GetValue("ProxyServer") as string);
            var pac = Sanitize(key.GetValue("AutoConfigURL") as string);
            into.Add(new ProxyInfo(scope, enabled, server, pac));
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            // Unreadable hive: skip rather than fail the whole inspection.
        }
    }

    /// <summary>Drops embedded credentials ("scheme://user:pass@host") and query strings before the value is stored or logged.</summary>
    private static string? Sanitize(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var withoutCredentials = Regex.Replace(value.Trim(), @"://[^/@\s;]+@", "://", RegexOptions.CultureInvariant);
        var query = withoutCredentials.IndexOf('?');
        return query >= 0 ? withoutCredentials[..query] : withoutCredentials;
    }
}
