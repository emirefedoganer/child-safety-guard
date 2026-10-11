using ChildSafetyGuard.Core.Abstractions;
using ChildSafetyGuard.Core.Accounts;
using ChildSafetyGuard.Core.Firewall;
using ChildSafetyGuard.Core.Guardian;
using ChildSafetyGuard.Core.Models;
using ChildSafetyGuard.Core.Policy;

namespace ChildSafetyGuard.Core.Tests;

internal sealed class ManualTimeProvider : TimeProvider
{
    private DateTimeOffset _now = new(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);

    public override DateTimeOffset GetUtcNow() => _now;

    public void Advance(TimeSpan by) => _now += by;
}

internal sealed class InMemoryStateStore : IStateStore
{
    public AppState? Current { get; set; }
    public bool Unreadable { get; set; }
    public int SaveCount { get; private set; }

    public AppState? Load() => Unreadable ? throw new StateStoreException("unreadable") : Current;

    public void Save(AppState state)
    {
        Current = state;
        SaveCount++;
    }
}

internal sealed class FakeFirewall : IFirewallGateway
{
    public List<ExistingFirewallRule> Rules { get; } = new();
    public bool? ProfilesEnabled { get; set; } = true;
    public HashSet<string> FailRemoveFor { get; } = new();

    public IReadOnlyList<ExistingFirewallRule> ListManagedRules() => Rules.ToList();

    public void AddRule(FirewallRuleSpec rule) =>
        Rules.Add(new ExistingFirewallRule(rule.Name, rule.ProgramPath, true, true, true));

    public void RemoveRule(string name)
    {
        if (FailRemoveFor.Contains(name))
        {
            throw new InvalidOperationException("denied");
        }

        Rules.RemoveAll(r => r.Name == name);
    }

    public bool? AreAllProfilesEnabled() => ProfilesEnabled;
}

internal sealed class FakeResolver : IApplicationPathResolver
{
    public Dictionary<string, string[]> PathsByApplicationId { get; } = new();

    public IReadOnlyList<ResolvedApplication> Resolve(PolicyDocument policy) =>
        policy.BlockedApplications
            .Where(a => a.Enabled)
            .Select(a => new ResolvedApplication(a, PathsByApplicationId.GetValueOrDefault(a.Id) ?? Array.Empty<string>()))
            .ToList();
}

internal sealed class FakeInspector : INetworkInspector
{
    public NetworkSnapshot Snapshot { get; set; } = TestData.Snapshot();

    public NetworkSnapshot Capture() => Snapshot;
}

internal sealed class FakeInventory : IRuntimeInventory
{
    public RuntimeInventory Inventory { get; set; } = new(Array.Empty<string>(), Array.Empty<string>(), Array.Empty<string>());

    public RuntimeInventory Capture() => Inventory;
}

internal sealed class FakeAccounts : IAccountInspector
{
    public List<ProfileAccount> Profiles { get; } = new();
    public bool Throw { get; set; }

    public IReadOnlyList<ProfileAccount> GetProfiles(IReadOnlyCollection<string> onlyNames)
    {
        if (Throw)
        {
            throw new InvalidOperationException("netapi32 failed");
        }

        return Profiles
            .Where(p => onlyNames.Count == 0 || onlyNames.Contains(p.Name, StringComparer.OrdinalIgnoreCase))
            .ToList();
    }
}

internal sealed class RecordingSink : IFindingSink
{
    public List<Finding> Reported { get; } = new();

    public void Report(Finding finding) => Reported.Add(finding);
}

internal sealed class FakeFileSystem : IFileSystemReader
{
    private readonly HashSet<string> _files;

    public FakeFileSystem(IEnumerable<string> files)
    {
        _files = new HashSet<string>(files, StringComparer.OrdinalIgnoreCase);
    }

    public bool FileExists(string path) => _files.Contains(path);

    public IEnumerable<string> EnumerateDirectoryNames(string directory)
    {
        var prefix = directory.TrimEnd('\\') + "\\";
        return _files
            .Where(f => f.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            .Select(f => f[prefix.Length..])
            .Where(rest => rest.Contains('\\'))
            .Select(rest => rest[..rest.IndexOf('\\')])
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public IEnumerable<string> EnumerateFileNames(string directory)
    {
        var prefix = directory.TrimEnd('\\') + "\\";
        return _files
            .Where(f => f.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            .Select(f => f[prefix.Length..])
            .Where(rest => !rest.Contains('\\'))
            .ToList();
    }
}

internal static class TestData
{
    public const int FastHashIterations = 1_000;
    public const string Passphrase = "correct horse battery";

    public static ProtectedLocations Protected() =>
        new(new[] { @"C:\Windows", @"C:\Program Files\ChildSafetyGuard", @"C:\ProgramData\ChildSafetyGuard" });

    public static PolicyValidator Validator() => new(Protected());

    public static AdapterInfo Adapter(
        string id = "{wifi}",
        string name = "Wi-Fi",
        string description = "Intel Wi-Fi 6 AX201",
        AdapterKind kind = AdapterKind.Wireless,
        bool up = true,
        string[]? dns = null,
        string[]? gateways = null) =>
        new(id, name, description, kind, up, new[] { "192.168.1.20" }, gateways ?? new[] { "192.168.1.1" }, dns ?? new[] { "192.168.1.1" });

    public static NetworkSnapshot Snapshot(IEnumerable<AdapterInfo>? adapters = null, IEnumerable<ProxyInfo>? proxies = null) =>
        new(
            new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero),
            (adapters ?? new[] { Adapter() }).ToList(),
            (proxies ?? Array.Empty<ProxyInfo>()).ToList());

    /// <summary>A store that already contains a guardian, plus a valid session for it.</summary>
    public static (InMemoryStateStore Store, ManualTimeProvider Time, GuardianManager Guardian, GuardianSession Session) Guarded()
    {
        var store = new InMemoryStateStore();
        var time = new ManualTimeProvider();
        var guardian = new GuardianManager(store, time, FastHashIterations);
        guardian.Initialize(Passphrase);
        var session = guardian.Authenticate(Passphrase).Session!;
        return (store, time, guardian, session);
    }

    public static string Rule(string appId, string path) => FirewallPlanner.RuleName(appId, path);
}
