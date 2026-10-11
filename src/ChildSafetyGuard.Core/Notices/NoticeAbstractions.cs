using ChildSafetyGuard.Core.Models;

namespace ChildSafetyGuard.Core.Notices;

/// <param name="ImagePath">Full path of the running executable, or null if Windows would not tell us.</param>
public sealed record RunningProcess(string Name, string? ImagePath, int SessionId);

public interface IProcessLocator
{
    /// <summary>Finds running processes by name. Only the names that are asked for are looked at.</summary>
    IReadOnlyList<RunningProcess> FindProcesses(IReadOnlyCollection<string> processNames);
}

public interface IBlockNoticeDisplay
{
    /// <summary>Shows the notice to whoever is signed in to the given Windows session. Must not block.</summary>
    void Show(int sessionId, BlockNotice notice);
}
