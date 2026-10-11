# 4. Repository and solution structure

```
ChildSafetyGuard/
├─ ChildSafetyGuard.sln
├─ Directory.Build.props              shared compiler settings (nullable, latest C#)
├─ README.md
├─ docs/
│  ├─ 01-threat-model.md
│  ├─ 02-security-architecture.md
│  ├─ 03-api-comparison.md
│  ├─ 04-repository-structure.md      (this file)
│  ├─ 05-roadmap.md
│  └─ PRIVACY.md                      what is / is not monitored; feature checklist
├─ scripts/
│  ├─ Install-Service.ps1             create the visible Windows service (auto-start, restart-on-failure)
│  └─ Uninstall-Service.ps1
├─ src/
│  ├─ ChildSafetyGuard.Core/          net8.0, no Windows/networking dependencies — all decisions live here
│  │  ├─ Models/                      AppState, PolicyDocument, NetworkSnapshot, Finding, firewall records
│  │  ├─ Abstractions/                IStateStore, IFirewallGateway, INetworkInspector, IRuntimeInventory, …
│  │  ├─ Guardian/                    SecretHasher, GuardianManager (auth, lockout, recovery), GuardianSession
│  │  ├─ Policy/                      PolicyValidator, PolicyManager, ProtectedLocations
│  │  ├─ Paths/                       PathPatternExpander (bounded glob expansion)
│  │  ├─ Firewall/                    FirewallPlanner, FirewallReconciler (pure diff)
│  │  ├─ Network/                     NetworkChangeAnalyzer (explainable baseline comparison)
│  │  ├─ Detection/                   KnownToolCatalog, CircumventionMatcher
│  │  ├─ Enforcement/                 EnforcementEngine, EventIds, LoggerFindingSink
│  │  └─ TransparencyStatement.cs
│  ├─ ChildSafetyGuard.Windows/       net8.0-windows — implementations of the abstractions
│  │  ├─ DpapiStateStore.cs, StateDirectorySecurity.cs
│  │  ├─ WindowsFirewallGateway.cs    HNetCfg.FwPolicy2 COM
│  │  ├─ WindowsNetworkInspector.cs, ProxySettingsReader.cs
│  │  ├─ WindowsRuntimeInventory.cs   process / service / driver names
│  │  ├─ WindowsApplicationPathResolver.cs, UserProfiles.cs, WindowsFileSystemReader.cs
│  │  └─ ServiceCollectionExtensions.cs   AddChildSafetyGuard(...)
│  ├─ ChildSafetyGuard.Service/       Worker service (LocalSystem), Event Log logging
│  └─ ChildSafetyGuard.Cli/           `csg.exe` — guardian tool (UAC-elevated)
├─ tests/
│  └─ ChildSafetyGuard.Core.Tests/    xUnit; fakes for every Windows touchpoint
└─ (Phase 2) src/ChildSafetyGuard.Dashboard/   WPF guardian dashboard
```

## Dependency rules

* `Core` depends on nothing but `Microsoft.Extensions.Logging.Abstractions`. A unit test fails if it ever references an HTTP or
  socket assembly.
* `Windows` depends on `Core`; `Service` and `Cli` depend on `Windows`; nothing depends on `Service`/`Cli`.
* New Windows integrations are added as an interface in `Core.Abstractions` + an implementation in `Windows` + a fake in tests.

## Conventions

* Every enforcement or detection rule is pure and takes data in / findings out, so it can be tested without Windows.
* Findings carry **names and configuration only**. Adding a field that could hold content is a review blocker (see `PRIVACY.md`).
* Public constants such as event IDs and rule-name prefixes live in one place (`EventIds`, `FirewallPlanner`).
