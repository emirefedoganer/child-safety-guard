using ChildSafetyGuard.Core.Abstractions;

namespace ChildSafetyGuard.Windows;

/// <summary>Thin file-system reader that never throws on access problems: an unreadable folder simply yields nothing.</summary>
public sealed class WindowsFileSystemReader : IFileSystemReader
{
    public bool FileExists(string path)
    {
        try
        {
            return File.Exists(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return false;
        }
    }

    public IEnumerable<string> EnumerateDirectoryNames(string directory) =>
        Enumerate(directory, Directory.EnumerateDirectories);

    public IEnumerable<string> EnumerateFileNames(string directory) =>
        Enumerate(directory, Directory.EnumerateFiles);

    private static IEnumerable<string> Enumerate(string directory, Func<string, IEnumerable<string>> enumerate)
    {
        try
        {
            if (!Directory.Exists(directory))
            {
                return Array.Empty<string>();
            }

            return enumerate(directory).Select(p => Path.GetFileName(p) ?? string.Empty).ToList();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return Array.Empty<string>();
        }
    }
}
