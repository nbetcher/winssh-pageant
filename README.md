# WinSSH-Pageant

A Windows desktop bridge that lets PuTTY, Plink, WinSCP, and other Pageant-compatible clients use keys held by the Windows OpenSSH authentication agent. Private keys remain in OpenSSH; this application forwards agent requests.

## Install on Windows 10 or 11

Use the MSI matching your machine: `amd64` for Intel/AMD Windows 11, or `arm64` for Windows on ARM. A `386` build is also available for 32-bit Windows 10. ARM64 packages are cross-built and require device qualification.

Double-click the MSI and finish setup. It installs for the current user without requiring administrator rights, registers in Installed apps, adds a Start menu shortcut and a startup entry, and launches the application. Disable startup in **Settings > Apps > Startup** or **Task Manager > Startup apps**. Uninstall from Installed apps. Run the bridge without elevation.

The MSI retains the existing upgrade family for earlier per-user installations. A machine-wide installation must be removed separately because MSI upgrade detection is context-specific. Some older uninstallers forcibly stop all processes with the application name; close the older copy before upgrading and avoid running multiple portable copies during legacy upgrades.

Generated packages are unsigned unless a distributor signs them with an Authenticode certificate. Compare the package with its accompanying `SHA256SUMS.txt`; checksums verify integrity, not publisher identity. Never dismiss an antivirus detection solely because an executable was written in Go.

The Windows **OpenSSH Authentication Agent** service must be installed and running. The Windows optional-feature version is supported; a separate OpenSSH download is not required. If the service is disabled, enable it through Windows Services with administrator rights. Load keys using your normal account:

```powershell
ssh-add "$env:USERPROFILE\.ssh\id_ed25519"
ssh-add -l
```

The installer does not change the OpenSSH service or load, delete, or copy keys. Only one Pageant-compatible agent can claim the Pageant window and pipe at a time; exit an existing Pageant or older bridge before launching a portable copy.

## Tray and key window

The application appears as a key/plug icon in the notification area, possibly in the overflow menu. Right-click for **Show SSH keys**, **Signing notifications**, and **Exit**. Double-click also opens the key window. Exit stops the bridge without unloading keys from OpenSSH.

The native window lists the type, SHA256 fingerprint, and comment of every key currently loaded in the configured agent. **Refresh** retrieves the current list. Empty and unavailable/locked-agent states are distinct. Unloaded key files on disk do not appear. The list contains public metadata only.

Signing notifications are enabled by default and can be toggled for the current run. Windows notification settings and Do Not Disturb can suppress them. Notifications report requests passing through this bridge, including refusals. An OpenSSH client using the Windows agent directly bypasses the bridge and cannot trigger these notifications.

### Notification attribution

The standard agent protocol supplies a public key and data to sign; it does **not** carry the destination hostname or TCP port. An SSH authentication payload normally includes the requested username. Generic signatures, such as commit signatures, may have no SSH destination.

Windows supplies the process ID for named-pipe clients. Legacy `WM_COPYDATA` callers often supply no sender window; their conventional mapping-name thread ID can provide an **inferred** identity. Explicit SSH-client command-line destinations or a unique established TCP endpoint can provide an **inferred** destination. Inaccessible, ambiguous, forwarded, proxied, and unsupported connections display unavailable details. These labels are informational, not authorization decisions or proof that a server accepted authentication.

No private keys, signed payloads, full command lines, or notification history are written to disk. Connection details can be visible to someone looking at your screen.

## Command line

```text
winssh-pageant.exe [--sshpipe \\.\pipe\openssh-ssh-agent] [--no-pageant-pipe]
winssh-pageant.exe --show-keys
winssh-pageant.exe --exit
winssh-pageant.exe --version
```

`--sshpipe` selects another **local** pipe; remote SMB pipes are rejected. `--no-pageant-pipe` leaves legacy shared-memory IPC enabled. `--show-keys` opens the existing instance's window, or starts the application and opens it. `--exit` closes only an instance belonging to the same user at this exact executable path; it never kills by process name.

A portable ZIP contains the executable, README, and license. To start it at login, place a shortcut in the current user's `shell:startup` folder. Avoid a duplicate startup entry when using the MSI.

## Security boundary

The bridge follows the usual agent trust model: applications running as your Windows user can ask the agent to sign. Notifications are not approval prompts. The bridge forwards agent operations, including key-management operations, rather than imposing a confirmation policy. Use agent/key constraints and separate accounts when you need stronger isolation.

The Pageant pipe has a protected current-user-only ACL, rejects remote clients, bounds concurrent connections and incomplete-frame time, and validates framing. Legacy mappings must be owned by the current user and carry a bounded, terminated name. Requests are copied before forwarding. Requests and replies have allocation limits and deadlines; the UI remains responsive while legacy signing waits.

Each named-pipe client retains its own upstream connection so OpenSSH session-binding state survives across requests. Transport errors retire that session rather than reconnecting without its security state. Legacy shared-memory requests lack a persistent connection identity and explicitly reject the OpenSSH session-binding extension. The upstream agent ultimately determines supported algorithms and key constraints.

See [REVIEW.md](REVIEW.md) for review findings, verification evidence, and qualification limits.

## Build and verify

Prerequisites: Go matching `go.mod`, and .NET 8 SDK for MSI packaging. Downloads require network access. The build installs pinned resource/WiX tools under `.tools`, embeds the existing application icon and a Windows compatibility/DPI manifest, and preserves output in `build` and `release`.

```powershell
go test ./...
go vet -unsafeptr=false ./...
$env:WINSSH_DESKTOP_TEST = '1'
go test ./pageant -run TestDesktopNativeSmoke -count=1
$env:WINSSH_DESKTOP_TEST = $null
.\build.ps1 -Release -Architectures amd64,arm64,386
.\packaging\Test-Package.ps1
```

The vet pointer check is excluded for Win32 callback and mapping pointer boundaries; all other vet checks stay enabled. Native smoke tests briefly create a separate tray icon and popup without claiming production Pageant endpoints.

With a compatible C compiler available, also run `go test -race ./...` with `CGO_ENABLED=1`. This review passed the full race-enabled suite and native desktop tests using LLVM Clang on Windows 11, without disabling runtime pointer checks.

The default build targets `amd64` and `arm64`. `-ver 2.4.1` overrides `VERSION`. Release packaging emits MSI, ZIP, and SHA256 checksums and fails on resource, compiler, or packaging errors. Plain `go build` is useful for development but does not generate icon/manifest resources; use `build.ps1` for distribution.

## Release workflow

The **Go** workflow tests pull requests and pushes to `master`, builds all three MSI/ZIP architectures, inspects the packages, and tests installation, repair, and uninstall on its disposable Windows runner. Successful runs retain the packages and checksums as the `windows-packages` artifact; installer logs are retained even on failure.

For a release, update `VERSION` and add reviewed notes at `packaging/release-notes/<version>.md`, then commit the changes. Run **Release** manually on that commit's branch (the optional version must match `VERSION`), or push a tag named `v<version>`. Both paths validate the version and any existing tag, build and test that exact commit, verify transferred checksums, and prepare a **draft** GitHub release containing all MSI/ZIP packages and `SHA256SUMS.txt`. A missing tag targets the tested commit explicitly. An existing tag pointing elsewhere or an already published version is rejected.

For this version, the prepared release/tag is `v2.4.1`. Review the successful workflow and draft assets before publishing the draft. Local commits do not run Actions until pushed; creating this configuration does not publish a release or push a tag.

## Credits and license

Original project by Nathan Beals. Thanks to contributors to [wsl-ssh-pageant](https://github.com/benpye/wsl-ssh-pageant) and [WinCryptSSHAgent](https://github.com/buptczq/WinCryptSSHAgent) for Windows IPC examples. See [LICENSE](LICENSE).
