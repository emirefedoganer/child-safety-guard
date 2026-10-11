# 5. Phased development roadmap

## Phase 0 — Foundations (done)
Threat model, architecture, API comparison, repository layout, transparency statement.

## Phase 1 — MVP (this repository)
* Baseline network inspection (adapters, DNS, gateways, proxy settings) and explainable change analysis.
* Guardian authentication: passphrase, lockout, one-time recovery code, session tokens.
* Policy management: validated, guardian-only changes; Discord listed by default; per-profile targeting.
* Windows Firewall integration: idempotent reconcile of outbound block rules, drift repair, protected-path guard.
* Startup enforcement: Windows service, auto-start, restart-on-failure, reapply at boot and on network change.
* Circumvention *reporting*: known tool names, services, drivers (WinDivert), watch list.
* Block notice: when a blocked application is opened, the service shows the guardian's message (default: "GOTCHA! Bu uygulamayı kullanmak için annenden izin aldın mı?") in that user's session through `WTSSendMessage`; editable with `csg policy notice`.
* Account safety check: warns when a targeted Windows profile is an administrator (it could simply undo the restrictions) or does not exist yet.
* Encrypted local state (DPAPI + ACL), Event Log integration, CLI (`csg`), install scripts, unit tests.

**Exit criteria:** on a clean Windows 11 VM — install, `csg setup`, enable, Discord cannot connect for the target profile; reboot
keeps the rules; deleting a rule as admin is repaired within a minute; `csg recover` removes everything.

## Phase 2 — Guardian experience and deeper detection
* **WPF dashboard** (reads/writes the same state through the same managers; closing it changes nothing): status, findings
  timeline with explanations, policy editor, the transparency statement.
* **Richer block notice**: the MVP shows the guardian-written text in a standard message box (see below); Phase 2 adds a small
  visible helper window that can also show a picture. Always clearly the family's rule and who to talk to.
* Detection: Authenticode verification of identified executables (`WinVerifyTrust`), scheduled startup tasks, routing-table
  inspection (`GetIpForwardTable2`), WinHTTP proxy.
* Rediscovery on change: `FileSystemWatcher` on the application folders so a freshly updated Discord is blocked immediately.
* AppLocker policy generator (publisher rules) for editions that support it.
* DNS guidance / optional family DNS setting.

## Phase 3 — Hardening and distribution
* App Control for Business policy (audit mode first), WFP per-user filters if needed.
* Code-signed binaries and MSI/MSIX installer; reproducible builds.
* Optional TPM/CNG-sealed key instead of machine-scope DPAPI; tamper-evident local audit trail of guardian changes.
* Localisation (Turkish first), accessibility review, a printable "family agreement" template in the dashboard.
* External security review and a threat-model refresh.

## Phase 4 — Maintenance
Catalog updates by signed local package (never a silent download), compatibility testing per Windows release, telemetry-free by design.
