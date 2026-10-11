using ChildSafetyGuard.Core.Abstractions;
using ChildSafetyGuard.Core.Models;
using ChildSafetyGuard.Core.Paths;

namespace ChildSafetyGuard.Windows;

public sealed class WindowsApplicationPathResolver : IApplicationPathResolver
{
    private readonly IFileSystemReader _fileSystem;

    public WindowsApplicationPathResolver(IFileSystemReader fileSystem)
    {
        _fileSystem = fileSystem;
    }

    public IReadOnlyList<ResolvedApplication> Resolve(PolicyDocument policy)
    {
        var profiles = UserProfiles.Enumerate(policy.TargetProfiles.ToList());
        var resolved = new List<ResolvedApplication>();

        foreach (var app in policy.BlockedApplications.Where(a => a.Enabled))
        {
            var paths = PathPatternExpander.Expand(app.PathPatterns, profiles, _fileSystem, Environment.ExpandEnvironmentVariables);
            resolved.Add(new ResolvedApplication(app, paths));
        }

        return resolved;
    }
}
