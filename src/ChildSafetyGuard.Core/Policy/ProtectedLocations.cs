namespace ChildSafetyGuard.Core.Policy;

/// <summary>
/// Places and programs the product refuses to block, so a mistaken policy can never break Windows,
/// Windows security tooling, or the product itself.
/// </summary>
public sealed class ProtectedLocations
{
    private static readonly string[] CriticalExecutables =
    {
        "svchost.exe", "lsass.exe", "services.exe", "wininit.exe", "winlogon.exe", "csrss.exe", "smss.exe",
        "dwm.exe", "explorer.exe",
        // Windows Security / Defender components
        "msmpeng.exe", "mpcmdrun.exe", "nissrv.exe", "securityhealthservice.exe", "smartscreen.exe",
        // This product
        "childsafetyguard.service.exe", "csg.exe",
    };

    private readonly string[] _directoryPrefixes;

    public ProtectedLocations(IEnumerable<string> directories)
    {
        _directoryPrefixes = directories
            .Where(d => !string.IsNullOrWhiteSpace(d))
            .Select(d => d.Replace('/', '\\').TrimEnd('\\') + "\\")
            .ToArray();
    }

    public bool IsProtected(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return true;
        }

        var normalized = path.Replace('/', '\\');
        var fileName = normalized[(normalized.LastIndexOf('\\') + 1)..];
        if (CriticalExecutables.Contains(fileName, StringComparer.OrdinalIgnoreCase))
        {
            return true;
        }

        return _directoryPrefixes.Any(prefix => normalized.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
    }
}
