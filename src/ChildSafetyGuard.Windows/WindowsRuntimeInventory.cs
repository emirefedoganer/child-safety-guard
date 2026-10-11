using System.Diagnostics;
using System.ServiceProcess;
using ChildSafetyGuard.Core.Abstractions;
using ChildSafetyGuard.Core.Models;

namespace ChildSafetyGuard.Windows;

/// <summary>
/// Collects process names, Windows service names and kernel/file-system driver service names. Names only: no command
/// lines, no module lists, no file contents, no window titles.
/// </summary>
public sealed class WindowsRuntimeInventory : IRuntimeInventory
{
    public RuntimeInventory Capture()
    {
        var processes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var process in Process.GetProcesses())
        {
            try
            {
                processes.Add(process.ProcessName);
            }
            catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
            {
                // The process exited while we were looking at it.
            }
            finally
            {
                process.Dispose();
            }
        }

        return new RuntimeInventory(processes, ServiceNames(ServiceController.GetServices()), ServiceNames(ServiceController.GetDevices()));
    }

    private static HashSet<string> ServiceNames(ServiceController[] controllers)
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var controller in controllers)
        {
            names.Add(controller.ServiceName);
            controller.Dispose();
        }

        return names;
    }
}
