namespace ChildSafetyGuard.Core.Models;

/// <summary>
/// The guardian-configured policy. It is plain data: what to block, for which profiles,
/// and which extra process names the guardian wants reported.
/// </summary>
public sealed record PolicyDocument
{
    /// <summary>When false, the engine removes every firewall rule it manages.</summary>
    public bool EnforcementEnabled { get; init; }

    /// <summary>
    /// Windows profile folder names (e.g. "kid") that per-user path patterns are expanded for.
    /// Empty means every local user profile.
    /// </summary>
    public IReadOnlyList<string> TargetProfiles { get; init; } = Array.Empty<string>();

    public IReadOnlyList<BlockedApplication> BlockedApplications { get; init; } = Array.Empty<BlockedApplication>();

    /// <summary>Additional process names (no path) the guardian wants reported when running.</summary>
    public IReadOnlyList<string> ExtraWatchedProcessNames { get; init; } = Array.Empty<string>();

    /// <summary>Plain-language message shown to the device user when a blocked application is opened.</summary>
    public BlockNotice Notice { get; init; } = BlockNotice.Default;

    /// <summary>A fresh policy: Discord and Telegram are listed, but enforcement stays off until the guardian enables it.</summary>
    public static PolicyDocument CreateDefault() => new()
    {
        EnforcementEnabled = false,
        BlockedApplications = DefaultApplications.All,
    };
}

/// <summary>An application whose outbound network access is blocked by a Windows Firewall rule.</summary>
/// <param name="Id">Stable slug, e.g. "discord".</param>
/// <param name="DisplayName">Human-readable name shown in the UI and in firewall rule descriptions.</param>
/// <param name="PathPatterns">
/// Executable path patterns. Supports %LOCALAPPDATA%, %APPDATA%, %USERPROFILE% (expanded per profile),
/// other %ENV% variables, and * / ? wildcards in directory and file segments.
/// </param>
public sealed record BlockedApplication(
    string Id,
    string DisplayName,
    IReadOnlyList<string> PathPatterns,
    bool Enabled = true);

/// <summary>The message the device user sees when something is blocked. Written by the guardian.</summary>
public sealed record BlockNotice(string Title, string Message, string? ImagePath = null)
{
    public static BlockNotice Default { get; } = new(
        "GOTCHA!",
        "Bu uygulamayı kullanmak için annenden izin aldın mı?");
}

public static class DefaultApplications
{
    public static IReadOnlyList<BlockedApplication> All { get; } = new[]
    {
        new BlockedApplication(
            "discord",
            "Discord (desktop app)",
            new[]
            {
                @"%LOCALAPPDATA%\Discord\app-*\Discord.exe",
                @"%LOCALAPPDATA%\Discord\Update.exe",
                @"%LOCALAPPDATA%\DiscordPTB\app-*\DiscordPTB.exe",
                @"%LOCALAPPDATA%\DiscordPTB\Update.exe",
                @"%LOCALAPPDATA%\DiscordCanary\app-*\DiscordCanary.exe",
                @"%LOCALAPPDATA%\DiscordCanary\Update.exe",
            }),
        new BlockedApplication(
            "telegram",
            "Telegram (desktop app)",
            new[]
            {
                // Default per-user install from telegram.org, plus the older %LOCALAPPDATA% location.
                @"%APPDATA%\Telegram Desktop\Telegram.exe",
                @"%APPDATA%\Telegram Desktop\Updater.exe",
                @"%LOCALAPPDATA%\Telegram Desktop\Telegram.exe",
                @"%LOCALAPPDATA%\Telegram Desktop\Updater.exe",
            }),
    };
}
