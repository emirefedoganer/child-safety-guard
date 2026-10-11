using System.Security.Principal;

namespace ChildSafetyGuard.Windows;

public static class WindowsElevation
{
    public static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
}
