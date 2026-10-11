using System.Runtime.InteropServices;
using System.Text;
using ChildSafetyGuard.Core.Models;
using ChildSafetyGuard.Core.Notices;

namespace ChildSafetyGuard.Windows;

/// <summary>
/// Shows an ordinary Windows message box in a user's session with WTSSendMessage (documented Remote Desktop Services API),
/// which is how a service — isolated in session 0 — can talk to a signed-in user without injecting anything into their session.
/// </summary>
public sealed class WtsBlockNoticeDisplay : IBlockNoticeDisplay
{
    private const int MbIconInformation = 0x40;
    private const int MbSetForeground = 0x10000;
    private const int MbTopmost = 0x40000;

    public void Show(int sessionId, BlockNotice notice)
    {
        var style = MbIconInformation | MbSetForeground | MbTopmost;

        // Lengths are in bytes, not characters. bWait=false returns immediately; the box stays until it is closed.
        var ok = WTSSendMessage(
            IntPtr.Zero,
            sessionId,
            notice.Title,
            Encoding.Unicode.GetByteCount(notice.Title),
            notice.Message,
            Encoding.Unicode.GetByteCount(notice.Message),
            style,
            0,
            out _,
            false);

        if (!ok)
        {
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        }
    }

    [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern bool WTSSendMessage(
        IntPtr server,
        int sessionId,
        string title,
        int titleLength,
        string message,
        int messageLength,
        int style,
        int timeout,
        out int response,
        [MarshalAs(UnmanagedType.Bool)] bool wait);
}
