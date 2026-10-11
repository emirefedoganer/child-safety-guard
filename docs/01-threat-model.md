# 1. Threat model for parental-control circumvention

## Purpose and stance

Child Safety Guard is a **transparent, guardian-managed** control. It is installed by the person responsible for the
device, it is visible to the device user, and it is designed to be explained to them. The goal is to make "the easy way
around the family's rule" unavailable and to tell the guardian when something changes — not to win an arms race against
a determined, technically gifted young person. For such a user, technical controls buy time and set a clear boundary;
the durable protection is the agreement made with them. The threat model is written with that in mind.

## Assets

| Asset | Why it matters |
|---|---|
| Guardian policy (what is blocked, for whom) | Integrity: only the guardian may change it. |
| Guardian passphrase and recovery code | Confidentiality: they unlock every change. |
| Firewall rules owned by the product | Integrity and availability: they are the enforcement. |
| Network baseline | Integrity: a tampered baseline hides changes. |
| The device user's privacy | Confidentiality: the product must not become a surveillance channel. |
| Windows itself | Availability: a mistaken policy must never break networking or security tools. |

## Actors

| Actor | Capability assumed |
|---|---|
| **Guardian** | Windows administrator on the device; knows the passphrase. |
| **Device user (minor)** | Standard (non-admin) Windows user; may be technically very capable; has physical access to the device. |
| **Device user with admin rights** | Out of the supported configuration — see T1. |
| **Third party / malware** | Runs with the minor's privileges; may try to disable protection or read its data. |
| **Product misuse** | A guardian (or someone else) trying to use the product for covert surveillance. |

## Assumptions

* The minor uses a **standard user account**; the guardian keeps the only administrator account and its password.
* The device runs a supported Windows 11 build with Windows Defender Firewall enabled.
* Physical attacks (booting another OS, removing the disk, resetting firmware) are out of scope. BitLocker plus a
  firmware password are the recommended mitigations and are the guardian's responsibility.
* Other devices (phones, consoles, school PCs) are out of scope. Router- or DNS-level controls cover them.

## Threats

Likelihood/impact are for a capable 11-year-old with a standard account unless stated otherwise.

| # | Threat | Likelihood | Mitigation in this design | Residual risk / planned |
|---|---|---|---|---|
| T1 | Device user has administrator rights and simply stops the service, deletes rules or uninstalls | High if admin | Supported configuration requires a standard account. `csg status`, `csg policy enable` and `csg check` — and the service, once per change in the Event Log — warn when a targeted profile is in the local Administrators group (direct members only) or does not exist yet. | Not defensible against an administrator. This is by design and is stated openly. |
| T2 | Stopping or disabling the service | Low (needs admin) | Service starts automatically (SCM, delayed after BFE/MpsSvc), restarts on failure, reapplies the policy at every start and every cycle, and **firewall rules persist while the service is stopped**. | Rules removed by an admin are restored at the next cycle or restart. |
| T3 | Editing or deleting firewall rules | Low (needs admin) | Rule drift (disabled, flipped to allow, inbound, wrong path, duplicated) is detected and repaired each cycle. | As T1. |
| T4 | Copying or renaming the blocked program so a path-based rule no longer matches | **Medium** | None in the MVP beyond rediscovering new `app-*` version folders each cycle. | Planned: AppLocker/App Control publisher rules (Phase 2/3), which match the signed publisher rather than a path. Honest limitation. |
| T5 | Using the same service in a web browser (e.g. discord.com in Edge/Chrome) | **High** | None: program-based rules cannot see web use. | Planned: DNS-level filtering guidance and Family Safety web filtering (Phase 2). |
| T6 | VPN or proxy that tunnels around network-level blocks | Medium | Baseline comparison reports new tunnel/VPN-style adapters, activated adapters and new proxy/PAC settings; known VPN client names are reported. | Detection and explanation, not blocking. Installing a VPN client needs admin on a standard account. |
| T7 | DPI-circumvention tools (GoodbyeDPI, zapret, ByeDPI, PowerTunnel) | Medium | These do not change adapters or the public IP, so IP comparison cannot see them (and the product does not look up the public IP). Instead: process names, service names and driver names (e.g. WinDivert) are matched against a small public catalog. WinDivert needs administrator rights to load, so the standard-account assumption is the main control. | Renamed binaries evade name matching. Authenticode checks and scheduled-task inspection are planned (Phase 2). |
| T8 | Changing DNS (manual DNS, secure-DNS tools, browser DoH) | Medium | DNS changes per adapter are reported with before/after. | Browser-level DoH is not visible to the OS; browser policy controls are planned (Phase 3). |
| T9 | Tampering with or reading the state file | Low | Directory ACL: SYSTEM and Administrators only, no inheritance. File is DPAPI-encrypted (machine scope), written atomically. A tampered or corrupt file fails **static**: rules stay as they are and an error is logged. | A local administrator can read or replace it — by design. |
| T10 | Guessing the guardian passphrase | Low | CLI needs an elevated prompt first; PBKDF2-SHA256 (310 000 iterations); constant-time compare; 5 failures → 15-minute lockout (persisted); 10-minute sessions. | Weak passphrases remain weak; minimum length 8 is enforced. |
| T11 | Theft or misuse of the recovery code | Low | Shown once, stored only as a PBKDF2 hash, single use (rotated on use), shares the lockout counter. Recovery turns enforcement off and removes rules; it does not bypass anything else. | The guardian must store the code offline. |
| T12 | Supply-chain or update tampering | Low | Binaries live in `%ProgramFiles%` (admin-writable only). No auto-update, no network access. | Code signing and signed installer planned (Phase 3). |
| T13 | **The product itself becomes spyware** (scope creep, over-collection, covert use) | Design risk | No content collection of any kind; findings carry names and configuration only; minimal Event Log entries; **no networking code in the core library (enforced by a unit test)**; visible service; a plain-language transparency statement shown at setup and in `csg transparency`; no hiding or masquerading. | Governance: any new feature must pass the checklist in `docs/PRIVACY.md`. |
| T14 | False positives lead to unfair conclusions | Medium | Every finding states what was seen, why it might matter and *what it does not prove*; severities distinguish "Info" from "Warning"; nothing acts automatically on a finding. | Guardian judgement and conversation. |
| T15 | A mistaken policy breaks Windows or security tooling | Low | Validator rejects system folders, `..`, UNC paths, wildcard-only names; protected-path guard refuses system processes, Windows Defender components, the product's own files — even if a pattern resolves to them. Only rules named `ChildSafetyGuard.*` are ever listed, changed or removed. | — |
| T16 | Service crash loop or corrupted policy | Low | Each cycle is exception-isolated; invalid policy and unreadable state leave existing rules unchanged; SCM failure actions restart the service. | — |

## Out of scope (explicitly)

* Reading messages, browsing history, screens, keystrokes, camera or microphone.
* Hiding from, or interfering with, Windows security tooling.
* Defeating a determined local administrator.
* Remote monitoring or cloud reporting.
