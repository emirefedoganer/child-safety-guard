using ChildSafetyGuard.Core.Paths;
using Microsoft.Win32;

namespace ChildSafetyGuard.Windows;

/// <summary>Lists real user profiles from the Windows ProfileList registry key (not by scanning drives).</summary>
public static class UserProfiles
{
    private const string ProfileListKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";

    public static IReadOnlyList<UserProfile> Enumerate(IReadOnlyCollection<string>? onlyNames = null)
    {
        var profiles = new List<UserProfile>();
        using var root = Registry.LocalMachine.OpenSubKey(ProfileListKey);
        if (root is null)
        {
            return profiles;
        }

        foreach (var sid in root.GetSubKeyNames())
        {
            // Local/domain accounts (S-1-5-21-...) and Entra ID accounts (S-1-12-1-...); skips system service profiles.
            if (!sid.StartsWith("S-1-5-21-", StringComparison.Ordinal) && !sid.StartsWith("S-1-12-1-", StringComparison.Ordinal))
            {
                continue;
            }

            using var key = root.OpenSubKey(sid);
            var path = key?.GetValue("ProfileImagePath") as string;
            if (string.IsNullOrWhiteSpace(path))
            {
                continue;
            }

            var name = Path.GetFileName(path.TrimEnd('\\'));
            if (onlyNames is { Count: > 0 } && !onlyNames.Contains(name, StringComparer.OrdinalIgnoreCase))
            {
                continue;
            }

            profiles.Add(new UserProfile(name, path, sid));
        }

        return profiles;
    }
}
