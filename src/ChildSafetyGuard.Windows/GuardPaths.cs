namespace ChildSafetyGuard.Windows;

public static class GuardPaths
{
    public const string ServiceName = "ChildSafetyGuard";

    /// <summary>C:\ProgramData\ChildSafetyGuard — locked down to SYSTEM and Administrators by <see cref="StateDirectorySecurity"/>.</summary>
    public static string DefaultDataDirectory { get; } =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "ChildSafetyGuard");
}
