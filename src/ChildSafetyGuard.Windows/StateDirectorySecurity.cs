using System.Security.AccessControl;
using System.Security.Principal;

namespace ChildSafetyGuard.Windows;

/// <summary>Restricts the data directory to SYSTEM and the local Administrators group, with no inherited access.</summary>
public static class StateDirectorySecurity
{
    public static void Harden(string directory)
    {
        var info = new DirectoryInfo(directory);
        if (!info.Exists)
        {
            info.Create();
        }

        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

        const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        foreach (var sidType in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
        {
            security.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(sidType, null),
                FileSystemRights.FullControl,
                inherit,
                PropagationFlags.None,
                AccessControlType.Allow));
        }

        info.SetAccessControl(security);
    }
}
