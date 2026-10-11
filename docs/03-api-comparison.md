# 3. Comparison of relevant Microsoft-supported APIs

"Used" means used in the MVP; "Planned" means a later phase; "Not used" means deliberately avoided.

## Enforcement

| API / feature | What it gives | Pros | Cons | Decision |
|---|---|---|---|---|
| **Windows Defender Firewall COM API** (`INetFwPolicy2`, `INetFwRule`, ProgID `HNetCfg.FwPolicy2`) | Create/enumerate/remove rules (program, direction, action, profiles, grouping) | Documented and stable; persistent across reboot; visible to the user in Windows Security; no driver; easy to test behind an interface | Program-path based (breaks if the file is copied/renamed); applies to all users unless scoped with user lists; admin required | **Used** (MVP). Late-bound via `dynamic`. |
| `netsh advfirewall` / PowerShell `NetSecurity` cmdlets | Same rule set | Easy for admins | Text parsing, process spawn, localisation issues | Not used (fine for manual verification; `Get-NetFirewallRule -Group 'Child Safety Guard'`). |
| **Windows Filtering Platform** user-mode API (`FwpmEngineOpen0`, `FwpmFilterAdd0`, `fwpuclnt.dll`) | Filters with conditions (app id, **user id**, remote address, boot-time/persistent) | Per-user conditions; finer control; callout-free | P/Invoke surface is large; mistakes can disrupt networking; more review needed | **Planned** (Phase 2/3) only if per-user blocking beyond firewall rules is needed. Never callout drivers. |
| **AppLocker** (Local Security Policy / `Set-AppLockerPolicy`) | Allow/deny executables by path, hash or **publisher**, per user/group | Publisher rules survive renames/updates; native UI | Enforcement available on Pro/Enterprise/Education (not Home); requires Application Identity service | **Planned** (Phase 2): policy generator + guidance for Discord/GoodbyeDPI. |
| **App Control for Business / WDAC** | Kernel-enforced code integrity policy (signer, hash, path) | Strongest application control; tamper-resistant | Policy authoring complexity; edition and deployment tooling vary — verify per SKU; easy to lock oneself out | **Planned** (Phase 3), audit mode first. |
| **Standard user accounts** | Removes admin rights from the minor | Most effective single control; no code needed; blocks driver loading (WinDivert) | Needs guardian discipline and a separate admin account | **Required** by design; verified in docs and (Phase 2) by a warning in the CLI. |
| Microsoft Family Safety | Screen time, app limits, web filter, reports | Supported consumer product; no code | No public API for third-party apps; account-based | **Complementary**: recommended alongside this product, not integrated. |
| Legacy Windows Parental Controls (WPC) API | — | — | Removed from modern Windows | Not used. |

## Network inspection

| API | Use | Decision |
|---|---|---|
| `System.Net.NetworkInformation.NetworkInterface` (wraps IP Helper `GetAdaptersAddresses`) | Adapters, type, status, unicast addresses, gateways, DNS servers | **Used.** Documented, no extra permissions. |
| `NetworkChange.NetworkAddressChanged` | Event-driven re-inspection | **Used** (debounced 5 s) plus a timer. |
| Internet Settings registry values (`ProxyEnable`, `ProxyServer`, `AutoConfigURL`) | Per-user and machine proxy configuration | **Used** (loaded user hives only). |
| IP Helper `GetIpForwardTable2` | Routing table (is the default route via a tunnel?) | **Planned** (Phase 2). |
| Network List Manager (`INetworkListManager`) | Network category/connectivity | Planned if needed for profile awareness. |
| WinHTTP default proxy (`WinHttpGetDefaultProxyConfiguration`) | System-wide WinHTTP proxy | Planned (Phase 2). |
| Public-IP lookup via external web service | "Is a VPN active?" | **Not used**: leaves the device, adds an external dependency, and cannot detect local DPI tools. |
| Packet capture (WinDivert/Npcap/ETW network providers) | Traffic inspection | **Not used**: violates the privacy requirements. |

## Circumvention detection

| API | Use | Decision |
|---|---|---|
| `System.Diagnostics.Process.GetProcesses` (process **names** only) | Running tools | **Used.** |
| `ServiceController.GetServices` / `GetDevices` | Installed services and driver services (WinDivert, VPN services) | **Used.** |
| `WinVerifyTrust` (Authenticode) | Verify a found executable's signer | **Planned** (Phase 2): only on files already identified by name, never broad file scans. |
| Task Scheduler 2.0 COM (`Schedule.Service`) | Startup tasks that launch known tools | **Planned** (Phase 2). |
| WMI/ETW process-start events | Instant detection | Optional later; polling is sufficient and simpler. |
| Kernel hooks, minifilters, undocumented APIs | — | **Not used.** |

## Platform services

| API | Use | Decision |
|---|---|---|
| Windows Service + Service Control Manager (`Microsoft.Extensions.Hosting.WindowsServices`) | Auto-start, failure recovery, no UI dependency | **Used.** |
| Windows Event Log (`Microsoft.Extensions.Logging.EventLog`) | Minimal structured logging, stable event IDs | **Used.** |
| DPAPI (`ProtectedData`, machine scope) | Encrypt state at rest | **Used.** CNG/TPM-sealed keys or Windows Hello are options for Phase 3. |
| `File.Replace` + named mutex | Atomic, serialised writes | **Used.** |
| WPF (.NET 8) | Guardian dashboard | **Planned** (Phase 2). |
| UAC manifest (`requireAdministrator`) | Windows-level authorization for the CLI | **Used.** |
