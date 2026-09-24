# Windows 11 code and feature review

Review date: 2026-09-23. Runtime validation: Windows 11 Pro build 26200, x64, Go 1.27.0. Scope: all application sources, Win32 boundaries, both Pageant transports, OpenSSH exchanges, user-visible lifecycle, build/release automation, and MSI authoring. The existing installed 2.4.0 process and loaded user keys were preserved.

## Findings addressed

### High: fragile Win32 pointer lifetime and incorrect 32-bit MSG layout

The old `MSG` declaration omitted `lPrivate`, leaving 32-bit buffers smaller than the native structure. Raw `syscall.SyscallN` wrappers also did not provide the escape contract needed when a native call invokes Go callbacks and the stack moves. A real WM_COPYDATA signing test reproduced lost shutdown messages; incidental logging changed the outcome. Added the missing field and changed Win32 wrappers to `LazyProc.Call`, whose pointer arguments escape safely. The signing/shutdown regression passed 25 consecutive runs after the fix, without diagnostic logging, and ran successfully as a 32-bit process.

### High: permissive default pipe security and shared-memory trust

The bridge inherited go-winio's default pipe ACL rather than declaring a current-user-only policy. The mapping path also accepted a process owner SID in addition to the user SID, potentially expanding access for elevated processes. The pipe now uses a protected DACL containing only the current user; Windows-native tests inspect its effective descriptor. go-winio already rejects remote clients and reserves the first pipe instance; those protections are retained. Shared mappings now require the current user as owner, use the required access rights, validate the complete bounded NUL-terminated name, cap the legacy buffer, and copy requests before forwarding.

### High: connection-bound agent state was discarded

Every request formerly opened a new upstream connection. That cannot preserve OpenSSH session-binding state. Named-pipe clients now get independent persistent upstream sessions. A transport failure permanently retires the session instead of reconnecting without its prior security state. Legacy WM_COPYDATA cannot reliably establish a persistent peer identity and explicitly rejects `session-bind@openssh.com`. Real-pipe tests prove state survives two bridge requests and shutdown interrupts a stalled third request.

### Medium: malformed frames, misleading success, and partial writes

Request prefixes and minimum lengths were not consistently checked. Some upstream errors returned a nil error, and failure replies could be returned with missing payload bytes. Writes assumed complete progress. Both transport boundaries now validate complete frames, cap sizes before allocation, read full responses, handle partial writes, check deadline errors, and return a valid protocol failure on operational errors. Key-count, key-string, signing-payload, and notification parsers reject malformed data without logging signed data or key material.

### Medium: unbounded client work and slow-agent UI stalls

Unrestricted accepted connections could accumulate goroutines, and synchronous WM_COPYDATA signing occupied the application's only UI loop. Concurrent clients are capped at 32, partially transmitted frames have a two-minute deadline, upstream connection/write/reply waits are bounded, and shutdown closes clients and upstream sessions. Fully idle established channels remain open to support agent forwarding. The desktop UI and legacy IPC have separate locked Windows threads.

### Medium: application lifecycle and shutdown behavior

The old shutdown handler returned false for WM_QUERYENDSESSION and immediately posted quit, even if Windows later cancelled shutdown. Startup raced with a second process and a pipe failure could be logged without failing startup. Added a per-user/session mutex, synchronous pipe creation, correct session-query handling, native error reporting, and cleanup for tray/windows/connections. `--exit` verifies same user and exact executable path and waits for termination; it cannot terminate an unrelated Pageant or portable copy by name. GUI builds attach to a parent console for CLI output without replacing redirection or changing console modes.

### Medium: unsafe and unreliable build/release path

The old script recursively deleted a caller-supplied directory, used Invoke-Expression, relied on moving latest tools and WiX3, and could continue after MSI failures. The replacement uses argument arrays, pinned local build tools, validated paths/versions, checked exit codes, restored environment variables, retained artifacts, and architecture-specific resource/installer identities. CI release-version input is passed as data, not interpolated into script source. Executables include the application icon, version, asInvoker manifest, common controls v6, and DPI/Windows compatibility metadata.

### Feature completeness

- Tray presence, context-menu Exit, native public-key list, Refresh, keyboard navigation, and Explorer restart recovery are implemented.
- Signing notifications include the client and SSH username when available; explicit client arguments, PuTTY saved sessions, and unique TCP endpoints provide clearly labeled inferred destinations and nondefault ports.
- Per-user MSI packages install the executable/docs, register Installed apps, create an icon-bearing Start menu shortcut and a quoted HKCU Run startup entry, retain the upgrade family, and request unelevated launch after installation. StartupApproved is left to Windows, preserving user startup preferences.
- The README no longer claims that Windows' included OpenSSH is categorically unsupported or that antivirus alerts are automatically false positives.

## Verification evidence

- `go test ./...` and `go vet -unsafeptr=false ./...` pass. The disabled analyzer flags the narrow native callback/mapping pointer boundaries; other vet checks remain enabled.
- The full `go test -race -count=1 -timeout=90s ./...` suite also passes with `WINSSH_DESKTOP_TEST=1`, CGO enabled, and the installed LLVM Clang toolchain. Both race and pointer checks remain enabled. Native callback test data is allocated through Windows to match real IPC ownership. LLVM emits an `_errno` import linker warning, with no test failures.
- Real named pipes exercise fragmented requests/replies, framing rejection, error replies, ACLs, stateful sessions, and shutdown cancellation.
- An ephemeral Ed25519 fixture key signs through the real named-pipe bridge and through native WM_COPYDATA/shared memory. Both returned signatures verify against the original binary payload; no user private keys are involved.
- Native desktop tests register/find/remove the tray icon through the Windows shell, render and inspect a real ListView, exercise resize, Escape, empty/unavailable states, and simulated Explorer icon loss/recreation. These tests run independently of the production Pageant endpoints.
- A subprocess test verifies exact-path/user matching, graceful Exit, and actual tray removal on x64 and x86. Invoking the portable executable's `--exit` leaves the separately installed process alive with the same PID and start time.
- Live read-only OpenSSH enumeration matches `ssh-add`'s loaded-key count. Process/mapping attribution and named-pipe PID tests use Windows APIs; TCP inference uses an actual loopback connection owned by a test child.
- Metadata fuzzing completed 16,902,640 executions in approximately 11 seconds without a failure.
- `govulncheck` v1.1.4 reported no known reachable vulnerabilities on this source/toolchain snapshot. This is vulnerability-database evidence, not a guarantee against undiscovered defects.
- All three MSI/ZIP architectures build. WiX validation and the MSI COM inspection script check per-user scope, payload versions/architectures, embedded icon and GUI subsystem, startup/shortcut entries, custom-action sequencing, and unelevated launch. The x64 MSI payload was extracted and its executable's `--version` returned 2.4.1.

## Remaining qualification boundaries

The packages are unsigned: no publisher certificate was available. ARM64 binaries and test binaries are compile-checked but not executed on an ARM64 device. The full suite also runs as x86 on this x64 desktop. Windows 10 and non-English/high-DPI/multi-monitor desktops have not received a separate full manual compatibility pass.

Actual MSI install/repair/uninstall and legacy upgrade were not run on this workstation because it already has an active installed bridge. A guarded `packaging/Test-Install.ps1 -IsolatedTestMachine` workflow is included in CI to exercise installation, startup registration, shortcut/icon, automatic launch, repair/relaunch, and uninstall cleanup on a disposable Windows desktop. That workflow has not been run remotely as part of this local change. The existing 2.4.0 installer has a global process-name termination custom action; the new MSI cannot rewrite that cached legacy uninstaller. New installations use exact-path graceful shutdown.

Notifications are informational. The standard protocol does not supply a hostname/port, and a signature reply does not prove successful SSH login. Client-command/config destinations and network endpoints may identify an alias, proxy, or jump host. Legacy mapping process identity is inferred. Windows can suppress banners. Direct use of the underlying Windows agent bypasses the bridge. The review verified cryptographic transport, not a full PuTTY/WinSCP remote-server login matrix.

The current-user trust boundary intentionally permits agent operations from applications running as the user, including management operations. This bridge does not implement a per-signature approval policy, prevent same-user malware from using the upstream agent directly, or protect against an administrator.

## Primary references

- [SSH agent protocol, RFC 9987](https://www.rfc-editor.org/rfc/rfc9987.html): sign requests carry a key, data, and flags.
- [SSH authentication, RFC 4252 section 7](https://www.rfc-editor.org/rfc/rfc4252.html#section-7): username in authentication signed data.
- [GetNamedPipeClientProcessId](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeclientprocessid): kernel-supplied client PID.
- [GetExtendedTcpTable](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable): process-owned network endpoint lookup.
- [NtQueryInformationProcess](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess): optional native API compatibility limitations; target lookup fails gracefully.
- [Shell_NotifyIcon](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shell_notifyiconw): native tray lifecycle and notifications.
