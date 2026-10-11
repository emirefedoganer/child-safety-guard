using ChildSafetyGuard.Core.Abstractions;
using ChildSafetyGuard.Core.Accounts;

namespace ChildSafetyGuard.Windows;

public sealed class WindowsAccountInspector : IAccountInspector
{
    public IReadOnlyList<ProfileAccount> GetProfiles(IReadOnlyCollection<string> onlyNames)
    {
        var profiles = UserProfiles.Enumerate(onlyNames);
        var administrators = AdministratorGroup.TryGetMemberSids();

        return profiles
            .Select(p => new ProfileAccount(
                p.Name,
                p.Sid is null || administrators is null ? null : administrators.Contains(p.Sid)))
            .ToList();
    }
}
