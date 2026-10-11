using System.ComponentModel;
using System.Diagnostics;
using ChildSafetyGuard.Core.Notices;

namespace ChildSafetyGuard.Windows;

/// <summary>Finds processes by name and, for those few matches only, reads the executable path and session id.</summary>
public sealed class WindowsProcessLocator : IProcessLocator
{
    public IReadOnlyList<RunningProcess> FindProcesses(IReadOnlyCollection<string> processNames)
    {
        var found = new List<RunningProcess>();
        foreach (var name in processNames)
        {
            foreach (var process in Process.GetProcessesByName(name))
            {
                try
                {
                    found.Add(new RunningProcess(process.ProcessName, TryGetPath(process), process.SessionId));
                }
                catch (Exception ex) when (ex is InvalidOperationException or Win32Exception)
                {
                    // The process ended while we were looking at it.
                }
                finally
                {
                    process.Dispose();
                }
            }
        }

        return found;
    }

    private static string? TryGetPath(Process process)
    {
        try
        {
            return process.MainModule?.FileName;
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException or NotSupportedException)
        {
            return null;
        }
    }
}
