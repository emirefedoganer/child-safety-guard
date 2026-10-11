# 2. Windows security architecture

## Components

```
                         ┌────────────────────────────────────────────┐
  Guardian (admin) ─────►│  csg.exe  (CLI, requireAdministrator)      │
                         │  setup · policy · baseline · recover …     │
                         └───────────────┬────────────────────────────┘
                                         │ GuardianManager (passphrase, lockout)
                                         │ PolicyManager (needs GuardianSession)
                                         ▼
 ┌──────────────────────────────────────────────────────────┐
 │  state.dat   (DPAPI machine scope, ACL: SYSTEM + Admins)  │
 │  guardian hashes · policy · network baseline              │
 └───────────────┬──────────────────────────────────────────┘
                 │ read-only
                 ▼
 ┌──────────────────────────────────────────────────────────┐
 │  ChildSafetyGuard.Service  (LocalSystem, auto-start,      │
 │  depends on BFE + MpsSvc, restart-on-failure)             │
 │                                                          │
 │   EnforcementWorker ── timer + NetworkAddressChanged ──┐  │
 │                                                        ▼  │
 │   EnforcementEngine                                       │
 │     1 load + validate policy (fail static)                │
 │     2 resolve path patterns (ProfileList, bounded globs)  │
 │     3 plan → add/remove only ChildSafetyGuard.* rules     │
 │     4 inspect network vs baseline → findings              │
 │     5 match process/service/driver names → findings      │
 │     6 report NEW findings once                            │
 └──────┬───────────────┬──────────────────┬────────────────┘
        ▼               ▼                  ▼
  Windows Defender   .NET NetworkInterface  Windows Event Log
  Firewall (COM)     + registry (proxy)     (Application / "ChildSafetyGuard")
```

Core logic (`ChildSafetyGuard.Core`) has **no Windows and no networking dependencies**; every Windows touchpoint sits
behind an interface (`IFirewallGateway`, `IStateStore`, `INetworkInspector`, `IRuntimeInventory`,
`IApplicationPathResolver`). That is what makes the policy engine fully unit-testable and keeps the attack surface small.

## Trust boundaries

1. **Standard user ⟷ everything else.** The minor's account can read none of the product's files (ACL), cannot change
   services or firewall rules, and cannot start `csg.exe` without an administrator credential (UAC).
2. **Administrator ⟷ guardian.** A Windows administrator is *necessary* but not *sufficient* to change policy: the
   guardian passphrase is also required (this separates "an admin ran something" from "the guardian decided").
   An administrator can still uninstall or sabotage the product; the design does not pretend otherwise.
3. **Service ⟷ configuration.** The service only reads state. Only the CLI writes it, under a cross-process mutex and
   with atomic replace.

## Authentication and authorization

* **Windows authorization:** `csg.exe` carries a `requireAdministrator` manifest and re-checks `IsInRole(Administrator)`.
* **Guardian authentication:** passphrase hashed with PBKDF2-SHA256 (310 000 iterations, 16-byte random salt), verified in
  constant time. Five failures lock for 15 minutes; the counter is persisted so restarting the tool does not reset it.
* **Authorization token:** a successful login returns a `GuardianSession` (10 minutes). Every mutating `PolicyManager`
  method requires one; its constructor is `internal`, so no code path can change policy without authenticating.
* **Emergency recovery:** a one-time code (20 symbols from a 30-symbol alphabet, ≈98 bits) generated at setup, shown once,
  stored only as a hash. `csg recover` verifies it, **turns enforcement off, removes the firewall rules, sets a new
  passphrase and issues a new code**. It shares the lockout counter. Recovery is deliberately a "drop to safe/open" action
  rather than a back door into other functions.

## Data at rest

| Item | Location | Protection |
|---|---|---|
| State (guardian hashes, policy, baseline) | `C:\ProgramData\ChildSafetyGuard\state.dat` | DPAPI `LocalMachine` + fixed entropy; directory ACL protected (no inheritance) with SYSTEM and Administrators only; atomic replace; no backup copies of old hashes. |
| Binaries | `C:\Program Files\ChildSafetyGuard\` | Default Program Files ACL (administrators only write). |
| Event Log entries | Application log, source `ChildSafetyGuard` | Standard Windows log permissions. |

Machine-scope DPAPI is chosen because both the SYSTEM service and the elevated CLI must read the file. The ACL, not the
entropy, is the real access control. Nothing is ever transmitted off the device.

## Enforcement design

* **Mechanism:** outbound *block* rules per program path through the documented Windows Firewall COM API (`INetFwPolicy2`),
  grouped under "Child Safety Guard", named `ChildSafetyGuard.<appId>.<hash8>`, for all profiles.
* **Path resolution:** patterns such as `%LOCALAPPDATA%\Discord\app-*\Discord.exe` are expanded for each real user profile
  (from the `ProfileList` registry key), walking only the directories the pattern names. `TargetProfiles` limits blocking
  to specific profiles, so the guardian's own profile is not affected.
* **Idempotent reconcile:** desired rules are computed from policy, compared with existing managed rules, and only the
  difference is applied. Drift is repaired every cycle (default 60 s), on network change, and at service start.
* **Persistence:** firewall rules live in Windows itself, so they survive reboot and survive the service being stopped.
* **Fail-static:** unreadable state or invalid policy never removes or alters rules.
* **Guard rails:** protected-path list (Windows folder, system processes, Defender components, the product itself); only the
  product's own rule names are ever touched.

## Detection design (reporting only)

* **Network:** compare adapters (by stable GUID), DNS, gateways and proxy settings with the baseline; classify new adapters as
  tunnel-like by adapter type or well-known driver names, excluding adapters Windows creates itself (Teredo, 6to4, Hyper-V…).
* **Tools:** match process names, service names and driver-service names against a public catalog (GoodbyeDPI, zapret, WinDivert,
  common VPN and tunnel clients). Names only: no command lines, no modules, no file contents.
* **Explainability:** each finding has a code, severity, title, explanation (including what it does *not* prove), subject and
  evidence lines. Findings are de-duplicated and re-reported only if they disappear and return.

## Logging policy

Event Log only, minimal and non-personal. Information: rule changes (counts), findings (names/configuration). Warning: findings of
Warning severity, protected-path refusals. Error: unreadable state, invalid policy, firewall failures. File paths are **not**
logged at Information level (they contain user names). Event IDs are stable (see `EventIds`).

## Reliability

* Started by the Service Control Manager, `start= auto`, dependent on `BFE` and `MpsSvc`.
* Failure actions: restart after 5 s, 30 s, 60 s; reset after 24 h.
* The worker catches everything per cycle; the next cycle retries.
* GUI-independent: the future WPF dashboard talks to the same state file through the same managers; closing it changes nothing.
* No kernel drivers, hooks, undocumented APIs or packet interception.

## Update and removal

`Install-Service.ps1` copies binaries and (re)creates the service; `csg teardown` + `Uninstall-Service.ps1` remove rules,
service and files. The uninstall script refuses to leave orphaned rules unless `-Force` is used.
