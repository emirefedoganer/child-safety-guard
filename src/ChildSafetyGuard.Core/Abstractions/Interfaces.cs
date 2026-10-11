using ChildSafetyGuard.Core.Accounts;
using ChildSafetyGuard.Core.Models;

namespace ChildSafetyGuard.Core.Abstractions;

public interface IStateStore
{
    /// <summary>Returns null when nothing has been stored yet. Throws <see cref="StateStoreException"/> if the data exists but cannot be read.</summary>
    AppState? Load();

    void Save(AppState state);
}

public interface IFirewallGateway
{
    /// <summary>Lists only the rules this product owns (name prefix <see cref="Firewall.FirewallPlanner.NamePrefix"/>).</summary>
    IReadOnlyList<ExistingFirewallRule> ListManagedRules();

    void AddRule(FirewallRuleSpec rule);
    void RemoveRule(string name);

    /// <summary>True/false when known; null when it could not be determined.</summary>
    bool? AreAllProfilesEnabled();
}

public interface IApplicationPathResolver
{
    /// <summary>Expands the enabled applications' path patterns to existing executables on this machine.</summary>
    IReadOnlyList<ResolvedApplication> Resolve(PolicyDocument policy);
}

public interface INetworkInspector
{
    NetworkSnapshot Capture();
}

public interface IRuntimeInventory
{
    RuntimeInventory Capture();
}

public interface IFindingSink
{
    void Report(Finding finding);
}

public interface IFileSystemReader
{
    bool FileExists(string path);
    IEnumerable<string> EnumerateDirectoryNames(string directory);
    IEnumerable<string> EnumerateFileNames(string directory);
}

public interface IAccountInspector
{
    /// <summary>Profiles on this machine, limited to <paramref name="onlyNames"/> when it is not empty, with their administrator status.</summary>
    IReadOnlyList<ProfileAccount> GetProfiles(IReadOnlyCollection<string> onlyNames);
}
