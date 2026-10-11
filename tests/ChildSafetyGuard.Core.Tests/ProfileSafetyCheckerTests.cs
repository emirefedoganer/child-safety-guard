using ChildSafetyGuard.Core.Accounts;
using ChildSafetyGuard.Core.Models;

namespace ChildSafetyGuard.Core.Tests;

public class ProfileSafetyCheckerTests
{
    private static readonly string[] Kid = { "kid" };

    [Fact]
    public void ExplicitlyTargetedAdministrator_IsAWarning_WithTheFix()
    {
        var finding = Assert.Single(ProfileSafetyChecker.Assess(Kid, new[] { new ProfileAccount("kid", true) }));

        Assert.Equal("TARGET_PROFILE_IS_ADMINISTRATOR", finding.Code);
        Assert.Equal(FindingSeverity.Warning, finding.Severity);
        Assert.Contains("Standard user", finding.Explanation);
        Assert.Contains(finding.Evidence, e => e.Contains("kid"));
    }

    [Fact]
    public void AllProfilesTargeted_AdministratorIsOnlyANotice()
    {
        var finding = Assert.Single(ProfileSafetyChecker.Assess(
            Array.Empty<string>(),
            new[] { new ProfileAccount("parent", true), new ProfileAccount("kid", false) }));

        Assert.Equal(FindingSeverity.Notice, finding.Severity);
        Assert.Equal("profile:parent", finding.Subject);
        Assert.Contains("every profile", finding.Explanation);
    }

    [Fact]
    public void StandardOrUnknownAccounts_RaiseNothing()
    {
        Assert.Empty(ProfileSafetyChecker.Assess(Kid, new[] { new ProfileAccount("kid", false) }));
        Assert.Empty(ProfileSafetyChecker.Assess(Kid, new[] { new ProfileAccount("kid", null) }));
    }

    [Fact]
    public void ProfileThatDoesNotExistYet_IsExplained()
    {
        var finding = Assert.Single(ProfileSafetyChecker.Assess(Kid, Array.Empty<ProfileAccount>()));

        Assert.Equal("TARGET_PROFILE_NOT_FOUND", finding.Code);
        Assert.Equal(FindingSeverity.Notice, finding.Severity);
        Assert.Contains("first time the account signs in", finding.Explanation);
    }

    [Fact]
    public void ProfileNamesAreMatchedCaseInsensitively() =>
        Assert.Empty(ProfileSafetyChecker.Assess(new[] { "KID" }, new[] { new ProfileAccount("kid", false) }));

    [Fact]
    public void FindingKeys_AreStable_SoTheWarningIsReportedOnce()
    {
        var first = ProfileSafetyChecker.Assess(Kid, new[] { new ProfileAccount("kid", true) }).Single();
        var second = ProfileSafetyChecker.Assess(Kid, new[] { new ProfileAccount("kid", true) }).Single();

        Assert.Equal(first.Key, second.Key);
    }
}
