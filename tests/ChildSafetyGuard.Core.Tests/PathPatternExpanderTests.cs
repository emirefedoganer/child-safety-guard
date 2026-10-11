using ChildSafetyGuard.Core.Models;
using ChildSafetyGuard.Core.Paths;
using ChildSafetyGuard.Core.Util;

namespace ChildSafetyGuard.Core.Tests;

public class PathPatternExpanderTests
{
    private static readonly FakeFileSystem Disk = new(new[]
    {
        @"C:\Users\kid\AppData\Local\Discord\app-1.0.9001\Discord.exe",
        @"C:\Users\kid\AppData\Local\Discord\app-1.0.9002\Discord.exe",
        @"C:\Users\kid\AppData\Local\Discord\Update.exe",
        @"C:\Users\kid\AppData\Local\Discord\app-1.0.9002\notes.txt",
        @"C:\Users\parent\AppData\Local\Discord\app-1.0.1\Discord.exe",
        @"C:\Program Files\Other\other.exe",
    });

    private static readonly UserProfile Kid = new("kid", @"C:\Users\kid");
    private static readonly UserProfile Parent = new("parent", @"C:\Users\parent");

    private static IReadOnlyList<string> Expand(IEnumerable<string> patterns, params UserProfile[] profiles) =>
        PathPatternExpander.Expand(patterns, profiles, Disk, s => s);

    [Fact]
    public void ExpandsDiscordPatterns_ForTheTargetProfileOnly()
    {
        var paths = Expand(DefaultApplications.All[0].PathPatterns, Kid);

        Assert.Equal(3, paths.Count);
        Assert.All(paths, p => Assert.StartsWith(@"C:\Users\kid\", p));
        Assert.Contains(@"C:\Users\kid\AppData\Local\Discord\app-1.0.9002\Discord.exe", paths);
        Assert.Contains(@"C:\Users\kid\AppData\Local\Discord\Update.exe", paths);
    }

    [Fact]
    public void ExpandsForEveryProfile_WhenSeveralAreTargeted()
    {
        var paths = Expand(new[] { @"%LOCALAPPDATA%\Discord\app-*\Discord.exe" }, Kid, Parent);

        Assert.Equal(3, paths.Count);
        Assert.Contains(@"C:\Users\parent\AppData\Local\Discord\app-1.0.1\Discord.exe", paths);
    }

    [Fact]
    public void NonUserPatterns_AreExpandedOnce_AndOnlyIfTheFileExists()
    {
        Assert.Single(Expand(new[] { @"C:\Program Files\Other\other.exe" }, Kid, Parent));
        Assert.Empty(Expand(new[] { @"C:\Program Files\Other\missing.exe" }, Kid));
    }

    [Fact]
    public void WildcardsOnlyMatchTheLastSegmentAsFiles()
    {
        var paths = Expand(new[] { @"%LOCALAPPDATA%\Discord\app-*\*.exe" }, Kid);

        Assert.Equal(2, paths.Count); // notes.txt is not matched
    }

    [Theory]
    [InlineData(@"\\server\share\x.exe")]
    [InlineData(@"C:\Users\kid\..\parent\x.exe")]
    [InlineData(@"%UNKNOWN%\x\y.exe")]
    [InlineData(@"relative\x.exe")]
    public void RefusesUnsafeShapes(string pattern) => Assert.Empty(Expand(new[] { pattern }, Kid));

    [Fact]
    public void NoProfiles_MeansNoUserPaths() =>
        Assert.Empty(PathPatternExpander.Expand(DefaultApplications.All[0].PathPatterns, Array.Empty<UserProfile>(), Disk, s => s));
}

public class GlobMatcherTests
{
    [Theory]
    [InlineData("app-*", "app-1.0.9001", true)]
    [InlineData("app-*", "APP-1", true)]
    [InlineData("app-*", "xapp-1", false)]
    [InlineData("a?c", "abc", true)]
    [InlineData("a?c", "ac", false)]
    [InlineData("*", "", true)]
    [InlineData("WinDivert*", "WinDivert1.4", true)]
    [InlineData("a*b*c", "aXXbYYc", true)]
    [InlineData("a*b*c", "aXXbYY", false)]
    public void Matches(string pattern, string text, bool expected) =>
        Assert.Equal(expected, GlobMatcher.IsMatch(pattern, text));
}
