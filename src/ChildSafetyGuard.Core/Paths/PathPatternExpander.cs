using ChildSafetyGuard.Core.Abstractions;
using ChildSafetyGuard.Core.Util;

namespace ChildSafetyGuard.Core.Paths;

public sealed record UserProfile(string Name, string RootPath, string? Sid = null);

/// <summary>
/// Expands guardian-supplied executable path patterns into concrete, existing file paths.
/// Only walks the directories named by the pattern; it never scans a profile broadly.
/// </summary>
public static class PathPatternExpander
{
    private static readonly (string Token, string Suffix)[] UserTokens =
    {
        ("%LOCALAPPDATA%", @"\AppData\Local"),
        ("%APPDATA%", @"\AppData\Roaming"),
        ("%USERPROFILE%", string.Empty),
    };

    public static IReadOnlyList<string> Expand(
        IEnumerable<string> patterns,
        IReadOnlyList<UserProfile> profiles,
        IFileSystemReader fileSystem,
        Func<string, string> expandEnvironment)
    {
        var results = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var pattern in patterns)
        {
            foreach (var candidate in SubstituteTokens(pattern, profiles, expandEnvironment))
            {
                foreach (var path in Glob(candidate, fileSystem))
                {
                    if (seen.Add(path))
                    {
                        results.Add(path);
                    }
                }
            }
        }

        return results;
    }

    private static IEnumerable<string> SubstituteTokens(
        string pattern,
        IReadOnlyList<UserProfile> profiles,
        Func<string, string> expandEnvironment)
    {
        var usesUserToken = UserTokens.Any(t => pattern.Contains(t.Token, StringComparison.OrdinalIgnoreCase));
        if (!usesUserToken)
        {
            yield return expandEnvironment(pattern);
            yield break;
        }

        foreach (var profile in profiles)
        {
            var expanded = pattern;
            foreach (var (token, suffix) in UserTokens)
            {
                expanded = expanded.Replace(token, profile.RootPath.TrimEnd('\\') + suffix, StringComparison.OrdinalIgnoreCase);
            }

            yield return expandEnvironment(expanded);
        }
    }

    private static IEnumerable<string> Glob(string path, IFileSystemReader fileSystem)
    {
        var normalized = path.Replace('/', '\\');
        if (normalized.StartsWith(@"\\", StringComparison.Ordinal))
        {
            yield break; // UNC paths are never expanded.
        }

        var segments = normalized.Split('\\', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length < 2 || segments.Contains(".."))
        {
            yield break;
        }

        var drive = segments[0];
        if (drive.Length != 2 || !char.IsLetter(drive[0]) || drive[1] != ':')
        {
            yield break; // unresolved %TOKEN% or relative path
        }

        var current = new List<string> { drive };
        for (var i = 1; i < segments.Length; i++)
        {
            var segment = segments[i];
            var isLast = i == segments.Length - 1;
            var hasWildcard = segment.IndexOfAny(new[] { '*', '?' }) >= 0;
            var next = new List<string>();

            foreach (var parent in current)
            {
                if (!hasWildcard)
                {
                    next.Add(parent + "\\" + segment);
                    continue;
                }

                var names = isLast ? fileSystem.EnumerateFileNames(parent) : fileSystem.EnumerateDirectoryNames(parent);
                foreach (var name in names)
                {
                    if (GlobMatcher.IsMatch(segment, name))
                    {
                        next.Add(parent + "\\" + name);
                    }
                }
            }

            current = next;
        }

        foreach (var candidate in current)
        {
            if (fileSystem.FileExists(candidate))
            {
                yield return candidate;
            }
        }
    }
}
