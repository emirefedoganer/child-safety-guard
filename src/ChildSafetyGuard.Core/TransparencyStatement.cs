namespace ChildSafetyGuard.Core;

/// <summary>
/// The plain-language statement shown to the guardian during setup. The guardian is encouraged to read it
/// together with the device user.
/// </summary>
public static class TransparencyStatement
{
    public const string Text = """
        CHILD SAFETY GUARD - WHAT THIS SOFTWARE DOES

        It is a visible Windows service, started by the Windows Service Control Manager. It does not hide itself.
        Anyone who can open Services, Task Manager or Windows Firewall can see it and the rules it manages.

        WHAT IT DOES
          - Keeps Windows Firewall rules that block the network access of the applications the guardian listed.
          - Compares the device's network configuration (adapters, DNS servers, gateways, proxy settings) with
            a baseline recorded during setup, and reports differences with an explanation.
          - Looks at the NAMES of running processes, installed services and drivers for well-known VPN and
            DPI-circumvention tools, and reports matches with an explanation.
          - Shows a short message box (written by the guardian) when someone opens a blocked application. To do
            that it checks whether a process with the same NAME as a blocked program is running, and reads that
            process's file location to make sure it is really the blocked file.
          - Writes a short entry to the Windows Event Log (Application log, source "ChildSafetyGuard") when
            something changes or is found.

        WHAT IT DOES NOT DO
          - It does not read messages, websites, passwords, files, screens, camera or microphone.
          - It does not log keystrokes and does not take screenshots.
          - It does not upload anything. It has no server and makes no outbound connections of its own.
          - It does not hide, disguise or protect itself from Windows security tools, and it does not
            pretend to be another program.
          - It does not punish or act automatically on its findings.

        WHERE DATA LIVES
          - One encrypted file on this PC, readable only by Administrators and SYSTEM
            (C:\ProgramData\ChildSafetyGuard). Only the guardian's Windows administrator account can change it.
        """;
}
