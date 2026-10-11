using System.Text.RegularExpressions;
using ChildSafetyGuard.Core.Models;

namespace ChildSafetyGuard.Core.Policy;

public sealed class PolicyValidator
{
    public const int MaxApplications = 64;
    public const int MaxPatternsPerApplication = 16;

    private static readonly Regex IdPattern = new("^[a-z0-9][a-z0-9-]{0,31}$", RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly char[] InvalidProfileChars = { '\\', '/', ':', '*', '?', '"', '<', '>', '|' };

    private readonly ProtectedLocations _protected;

    public PolicyValidator(ProtectedLocations protectedLocations)
    {
        _protected = protectedLocations;
    }

    public bool IsProtectedPath(string path) => _protected.IsProtected(path);

    public IReadOnlyList<string> Validate(PolicyDocument policy)
    {
        var errors = new List<string>();

        if (policy.BlockedApplications.Count > MaxApplications)
        {
            errors.Add($"At most {MaxApplications} applications can be listed.");
        }

        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var app in policy.BlockedApplications)
        {
            if (string.IsNullOrEmpty(app.Id) || !IdPattern.IsMatch(app.Id))
            {
                errors.Add($"Application id '{app.Id}' is invalid (use 1-32 characters: a-z, 0-9, '-').");
            }
            else if (!ids.Add(app.Id))
            {
                errors.Add($"Duplicate application id '{app.Id}'.");
            }

            if (string.IsNullOrWhiteSpace(app.DisplayName) || app.DisplayName.Length > 100)
            {
                errors.Add($"Application '{app.Id}' needs a display name of 1-100 characters.");
            }

            if (app.PathPatterns is null || app.PathPatterns.Count == 0)
            {
                errors.Add($"Application '{app.Id}' needs at least one path pattern.");
            }
            else if (app.PathPatterns.Count > MaxPatternsPerApplication)
            {
                errors.Add($"Application '{app.Id}' has more than {MaxPatternsPerApplication} path patterns.");
            }
            else
            {
                foreach (var pattern in app.PathPatterns)
                {
                    ValidatePattern(app.Id, pattern, errors);
                }
            }
        }

        foreach (var name in policy.TargetProfiles)
        {
            if (string.IsNullOrWhiteSpace(name) || name.Length > 64 || name.IndexOfAny(InvalidProfileChars) >= 0)
            {
                errors.Add($"Target profile '{name}' is not a valid Windows profile folder name.");
            }
        }

        foreach (var process in policy.ExtraWatchedProcessNames)
        {
            if (string.IsNullOrWhiteSpace(process) || process.Length > 64 || process.IndexOfAny(new[] { '\\', '/', ':' }) >= 0)
            {
                errors.Add($"Watched process name '{process}' must be a bare process name without a path.");
            }
        }

        if (policy.Notice is null || string.IsNullOrWhiteSpace(policy.Notice.Title) || policy.Notice.Title.Length > 100 ||
            string.IsNullOrWhiteSpace(policy.Notice.Message) || policy.Notice.Message.Length > 500)
        {
            errors.Add("Block notice needs a title (max 100 characters) and a message (max 500 characters).");
        }

        return errors;
    }

    private static void ValidatePattern(string appId, string pattern, List<string> errors)
    {
        if (string.IsNullOrWhiteSpace(pattern))
        {
            errors.Add($"Application '{appId}' has an empty path pattern.");
            return;
        }

        var normalized = pattern.Replace('/', '\\');
        if (normalized.StartsWith(@"\\", StringComparison.Ordinal))
        {
            errors.Add($"Application '{appId}': network (UNC) paths are not supported.");
            return;
        }

        var segments = normalized.Split('\\', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length < 2)
        {
            errors.Add($"Application '{appId}': pattern '{pattern}' must name a file inside a folder.");
            return;
        }

        if (segments.Contains(".."))
        {
            errors.Add($"Application '{appId}': pattern '{pattern}' must not contain '..'.");
        }

        var first = segments[0];
        var rootedByToken = first.Length > 2 && first[0] == '%' && first[^1] == '%';
        var rootedByDrive = first.Length == 2 && char.IsLetter(first[0]) && first[1] == ':';
        if (!rootedByToken && !rootedByDrive)
        {
            errors.Add($"Application '{appId}': pattern '{pattern}' must start with a drive letter or an %ENV% variable.");
        }

        if (first.Contains('*') || first.Contains('?'))
        {
            errors.Add($"Application '{appId}': wildcards are not allowed in the first path segment.");
        }

        if (first.Equals("%SystemRoot%", StringComparison.OrdinalIgnoreCase) ||
            first.Equals("%windir%", StringComparison.OrdinalIgnoreCase))
        {
            errors.Add($"Application '{appId}': Windows system folders are protected and cannot be blocked.");
        }

        var file = segments[^1];
        if (!file.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        {
            errors.Add($"Application '{appId}': pattern '{pattern}' must end in .exe.");
        }
        else if (file[..^4].Trim('*', '?').Length == 0)
        {
            errors.Add($"Application '{appId}': the file name in '{pattern}' must not be only wildcards.");
        }
    }
}
