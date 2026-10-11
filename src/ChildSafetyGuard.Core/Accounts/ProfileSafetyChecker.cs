using ChildSafetyGuard.Core.Models;

namespace ChildSafetyGuard.Core.Accounts;

/// <summary>
/// Checks that the accounts the policy is meant to protect can actually be protected: an administrator account can stop
/// the service, delete the firewall rules or uninstall the software, so for it the restrictions are only a house rule.
/// </summary>
public static class ProfileSafetyChecker
{
    /// <param name="requestedProfiles">Profile names from the policy; empty means "all profiles".</param>
    /// <param name="found">The profiles that exist on this machine and match the request.</param>
    public static IReadOnlyList<Finding> Assess(IReadOnlyCollection<string> requestedProfiles, IReadOnlyList<ProfileAccount> found)
    {
        var findings = new List<Finding>();
        var explicitlyTargeted = requestedProfiles.Count > 0;

        foreach (var name in requestedProfiles)
        {
            if (!found.Any(p => string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase)))
            {
                findings.Add(new Finding(
                    "TARGET_PROFILE_NOT_FOUND",
                    FindingSeverity.Notice,
                    $"No Windows profile named '{name}' exists yet",
                    "Nothing is blocked for this profile. Windows creates a profile folder the first time the account signs in, " +
                    "so this is expected if the account has not been used yet; it can also be a typo. " +
                    "The folder name under C:\\Users is what counts (see 'csg profiles').",
                    "profile:" + name,
                    new[] { $"Requested profile: {name}" }));
            }
        }

        foreach (var profile in found.Where(p => p.IsAdministrator == true))
        {
            findings.Add(new Finding(
                "TARGET_PROFILE_IS_ADMINISTRATOR",
                explicitlyTargeted ? FindingSeverity.Warning : FindingSeverity.Notice,
                $"Windows account '{profile.Name}' has administrator rights",
                "Someone using an administrator account can stop the service, delete the firewall rules or uninstall this " +
                "software in a few clicks, so for that account the restrictions only work as a house rule. " +
                (explicitlyTargeted
                    ? "For a child's account, change it to a Standard user (Settings > Accounts > Other users > Change account type) " +
                      "and keep the only administrator password to yourself."
                    : "No profile was selected, so blocking applies to every profile, including administrator accounts. " +
                      "If this is your own account, that may be fine; use 'csg policy target-profiles' to limit blocking to the child's account.") +
                " Membership is checked for direct members of the local Administrators group only.",
                "profile:" + profile.Name,
                new[] { $"Profile: {profile.Name}", "Member of: local Administrators group" }));
        }

        return findings;
    }
}
