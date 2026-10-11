# Child Safety Guard

A **transparent, guardian-managed** Windows 11 parental-control service written in C# / .NET 8. A parent or legal guardian uses it to
keep chosen applications (Discord and Telegram are listed by default) from reaching the network on a child's account, and to be told — with an
explanation — when the device's network setup changes or a well-known VPN / DPI-circumvention tool (GoodbyeDPI, WinDivert, …) shows up.

It is **not** spyware: it is visible in Services and Task Manager, does not hide or disguise itself, reads no content (no messages,
screens, passwords, keystrokes, websites), and sends nothing anywhere. See [docs/PRIVACY.md](docs/PRIVACY.md).

> **Status: MVP.** The whole solution builds with 0 errors and 0 warnings on .NET 8, and the 119 unit tests of
> `ChildSafetyGuard.Core` pass. What has **not** been done yet: running the Windows layer (Windows Firewall COM calls, DPAPI store,
> service host, CLI) on an actual Windows 11 machine. That code was only compiled (cross-compiled on macOS with
> `-p:EnableWindowsTargeting=true`), so validate it on a Windows 11 VM before using it on a real device.

## How it works (one paragraph)

The guardian runs `csg setup` (elevated) to choose a passphrase, receive a one-time recovery code and record a network baseline.
The Windows service reads the encrypted policy and keeps outbound **block** rules in Windows Defender Firewall for each listed
application's executables (expanded for each user profile, e.g. `%LOCALAPPDATA%\Discord\app-*\Discord.exe`). Every minute and after any
network change it repairs drifted rules, compares the network with the baseline and checks process/service/driver *names* against a
small public catalog, writing short entries to the Windows Event Log. Rules live in Windows itself, so they survive reboots and a
stopped service.

## Documentation

1. [Threat model](docs/01-threat-model.md)
2. [Windows security architecture](docs/02-security-architecture.md)
3. [API comparison](docs/03-api-comparison.md)
4. [Repository structure](docs/04-repository-structure.md)
5. [Roadmap](docs/05-roadmap.md)
6. [Privacy statement](docs/PRIVACY.md)

## Build and test

```powershell
dotnet build
dotnet test tests/ChildSafetyGuard.Core.Tests       # runs on Windows, macOS or Linux
```

## Quick start (from the release)

1. Download **`ChildSafetyGuard-win-x64.zip`** from the [latest release](../../releases/latest) and unzip it.
2. Open **PowerShell as Administrator** in the unzipped folder and run:

```powershell
Get-ChildItem -Recurse | Unblock-File                                       # remove the "downloaded from the internet" mark
powershell -ExecutionPolicy Bypass -File .\scripts\Install-Service.ps1       # install the service (this run only)
& "$env:ProgramFiles\ChildSafetyGuard\cli\csg.exe" setup                    # passphrase, recovery code, network baseline
& "$env:ProgramFiles\ChildSafetyGuard\cli\csg.exe" policy enable            # start blocking
```

Notes:

* Windows blocks `.ps1` scripts by default; `-ExecutionPolicy Bypass` lifts that for this one run only and changes no system setting.
* The program files are **not code-signed**, so SmartScreen or Windows Security may warn. The package is built by the workflow in
  `.github/workflows/build.yml` from the source in this repository.
* `csg setup` prints a one-time **recovery code** - write it down and keep it somewhere safe. Run `csg policy list` before
  `policy enable` to see what will be blocked (Discord and Telegram Desktop by default).
* Try it in a Windows VM first: the Windows-specific parts have not yet been exercised on a real machine.
* Every push also builds a package as a workflow artifact (Actions -> latest run -> Artifacts) if you want a newer build than the release.

## Build and install from source (Windows 11/10, elevated PowerShell)

```powershell
dotnet publish src/ChildSafetyGuard.Service -c Release -r win-x64 --self-contained false -o artifacts/service
dotnet publish src/ChildSafetyGuard.Cli     -c Release -r win-x64 --self-contained false -o artifacts/cli
.\scripts\Install-Service.ps1

& "$env:ProgramFiles\ChildSafetyGuard\cli\csg.exe" setup
& "$env:ProgramFiles\ChildSafetyGuard\cli\csg.exe" profiles                       # find the child's profile folder name
& "$env:ProgramFiles\ChildSafetyGuard\cli\csg.exe" policy target-profiles <name>  # block only for that profile
& "$env:ProgramFiles\ChildSafetyGuard\cli\csg.exe" policy enable
```

## Guardian commands (`csg`, always elevated)

| Command | Needs passphrase | What it does |
|---|---|---|
| `setup` | creates it | Shows the transparency statement, sets passphrase, prints the recovery code once, records the baseline |
| `status` | no | Configuration, service state, managed rule count |
| `check` | no | Read-only: compares network to baseline and looks for known tools |
| `policy list` | no | Shows applications and patterns |
| `policy enable` / `disable` | yes | Turn enforcement on / off (off removes the rules) |
| `policy add <id> "<Name>" <pattern>…` | yes | Block another application's executables |
| `policy remove <id>` / `policy toggle <id> on\|off` | yes | Remove / pause one application |
| `policy target-profiles [name…]` | yes | Limit blocking to specific Windows profiles (none = all); warns if one is an administrator or does not exist yet |
| `policy notice ["title" "message"]` | to change | Show or set the message box shown when a blocked app is opened (default: GOTCHA! …annenden izin aldın mı?) |
| `policy watch [process…]` | yes | Extra process names to report |
| `baseline capture` / `show` | yes / no | Re-record or show the baseline |
| `passphrase` | yes | Change the passphrase |
| `recover` | recovery code | Emergency: enforcement off, rules removed, new passphrase and code |
| `teardown` | yes | Enforcement off + rules removed (run before uninstalling) |

## Known limitations (also in the threat model)

* **Browser use is not blocked.** Rules are per program; discord.com in a web browser needs DNS-level or Family Safety web filtering.
* **Path-based rules** do not follow a copied or renamed executable. Publisher-based AppLocker/App Control rules are planned.
* **Detection is by name.** Renamed tools evade it; findings are leads, not proof.
* **An administrator can always undo it.** Keep the child on a standard account and keep the only admin password to yourself. `csg status`, `csg policy enable` and `csg check` warn when a targeted profile is an administrator (direct membership of the local Administrators group only; nested groups are not expanded).
* The WPF dashboard and a block-notice window with a picture are Phase 2. Today the notice is a plain Windows message box.

## Using it well

Software like this works best as part of an agreement with the person it applies to: explain what it does (the statement in
`csg setup` is written for that), agree what is allowed and why, and treat findings as a reason to talk.
