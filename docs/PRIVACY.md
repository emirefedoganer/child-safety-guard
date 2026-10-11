# Privacy: what is and is not monitored

This is the plain-language statement shown by `csg setup` and `csg transparency`. It is meant to be read together with
the person who uses the device.

## What the software looks at

| Looks at | Purpose | Kept |
|---|---|---|
| Names of network adapters, whether they are up, their type, DNS servers, gateways, local addresses | Notice when the network setup changes (e.g. a VPN adapter appears) | In the encrypted baseline (only what was present at setup) |
| System and per-user proxy settings (server, auto-config URL without credentials/query) | Notice proxies | In the baseline |
| Names of running processes, installed services and drivers | Notice well-known VPN / DPI-circumvention tools | Not stored; only matching names appear in a finding |
| Whether a process with the same name as a blocked program is running; for those few matches only, its file location and Windows session | Show the guardian's message in the right user's session, and only if it really is the blocked file | Not stored |
| Windows Firewall rules whose name starts with `ChildSafetyGuard.` | Keep the configured blocks in place | Rules live in Windows itself |

## What it never looks at

Messages, websites visited, search terms, passwords, file contents, documents, screen contents, camera, microphone, keystrokes,
clipboard, location. It does not look up your public IP address. It does not read command lines, window titles or program
memory. The only program whose file location is read is one whose name matches a blocked application.

## Where data goes

Nowhere. There is no server, no account, no telemetry and no update check. The core library contains no networking code (a unit
test enforces this). Data is one encrypted file on the PC, readable only by administrators.

## What is logged

Short entries in the Windows Event Log (Application, source `ChildSafetyGuard`): rule changes (counts), findings (what was seen and
why it may matter), errors. No file paths at Information level, no user content.

## Transparency

The service is visible in Services and Task Manager, the firewall rules are visible in Windows Security (group "Child Safety Guard"),
and the software does not hide itself or pretend to be something else. Findings are leads for a conversation, never proof, and
nothing happens to the device user automatically because of one.

## Checklist for any new feature

1. Does it need content, or would names/configuration do? Use names/configuration.
2. Is it visible to the device user? It must be.
3. Does anything leave the device? It must not.
4. Can a false positive be explained in one sentence? The finding must say what it does *not* prove.
5. Is it in the transparency statement? Update it before shipping.
