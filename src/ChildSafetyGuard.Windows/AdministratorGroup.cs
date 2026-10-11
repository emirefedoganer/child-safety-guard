using System.Runtime.InteropServices;
using System.Security.Principal;

namespace ChildSafetyGuard.Windows;

/// <summary>
/// Reads the direct members of the local Administrators group with the documented NetLocalGroupGetMembers API.
/// The group is found by its well-known SID, so this works on any display language.
/// </summary>
internal static class AdministratorGroup
{
    private const int MaxPreferredLength = -1;

    /// <summary>SIDs of direct members, or null when the group could not be read. Nested group membership is not expanded.</summary>
    public static HashSet<string>? TryGetMemberSids()
    {
        try
        {
            var qualified = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null)
                .Translate(typeof(NTAccount)).Value;
            var groupName = qualified[(qualified.IndexOf('\\') + 1)..];

            var status = NetLocalGroupGetMembers(null, groupName, 0, out var buffer, MaxPreferredLength, out var entriesRead, out _, IntPtr.Zero);
            if (status != 0)
            {
                return null;
            }

            try
            {
                var sids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                for (var i = 0; i < entriesRead; i++)
                {
                    // LOCALGROUP_MEMBERS_INFO_0 is a single PSID field.
                    var sidPointer = Marshal.ReadIntPtr(buffer, i * IntPtr.Size);
                    sids.Add(new SecurityIdentifier(sidPointer).Value);
                }

                return sids;
            }
            finally
            {
                NetApiBufferFree(buffer);
            }
        }
        catch (Exception)
        {
            // Best effort: "unknown" is reported as no finding rather than a false alarm.
            return null;
        }
    }

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int NetLocalGroupGetMembers(
        [MarshalAs(UnmanagedType.LPWStr)] string? serverName,
        [MarshalAs(UnmanagedType.LPWStr)] string localGroupName,
        int level,
        out IntPtr buffer,
        int preferredMaximumLength,
        out int entriesRead,
        out int totalEntries,
        IntPtr resumeHandle);

    [DllImport("netapi32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int NetApiBufferFree(IntPtr buffer);
}
