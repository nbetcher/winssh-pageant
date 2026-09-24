//go:build windows

package pageant

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
	"unsafe"

	"github.com/ndbeals/winssh-pageant/internal/security"
	"github.com/ndbeals/winssh-pageant/openssh"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	clientKernel32             = windows.NewLazySystemDLL("kernel32.dll")
	clientGetProcessIDOfThread = clientKernel32.NewProc("GetProcessIdOfThread")
	clientNtQueryProcess       = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtQueryInformationProcess")
	clientGetTCPTable          = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetExtendedTcpTable")
)

type connectionTarget struct {
	user, host string
	port       uint16
	source     string
	session    string
}

type clientInfo struct {
	pid      uint32
	name     string
	inferred bool
	started  uint64
	target   connectionTarget
}

func clientFromPipe(conn net.Conn) clientInfo {
	fd, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return clientInfo{}
	}
	var pid uint32
	if windows.GetNamedPipeClientProcessId(windows.Handle(fd.Fd()), &pid) != nil {
		return clientInfo{}
	}
	return clientFromProcess(pid)
}

// The legacy protocol does not authenticate a PID. PuTTY embeds its thread ID
// in this mapping name; treat that convention as a hint, never authorization.
func clientFromMapping(name string) clientInfo {
	const prefix = "PageantRequest"
	if !strings.HasPrefix(name, prefix) || len(name) != len(prefix)+8 {
		return clientInfo{}
	}
	for _, digit := range name[len(prefix):] {
		if !strings.ContainsRune("0123456789abcdefABCDEF", digit) {
			return clientInfo{}
		}
	}
	tid, err := strconv.ParseUint(name[len(prefix):], 16, 32)
	if err != nil || tid == 0 {
		return clientInfo{}
	}
	thread, err := windows.OpenThread(windows.THREAD_QUERY_LIMITED_INFORMATION, false, uint32(tid))
	if err != nil {
		return clientInfo{}
	}
	defer func() { _ = windows.CloseHandle(thread) }()
	pid, _, _ := clientGetProcessIDOfThread.Call(uintptr(thread))
	client := clientFromProcess(uint32(pid))
	client.inferred = true
	return client
}

func ownProcess(pid uint32) (windows.Handle, error) {
	if pid == 0 {
		return 0, fmt.Errorf("missing client process")
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return 0, err
	}
	var token windows.Token
	if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
		_ = windows.CloseHandle(process)
		return 0, err
	}
	defer func() { _ = token.Close() }()
	user, err := token.GetTokenUser()
	ourSID, ownErr := security.GetUserSID()
	if err != nil || ownErr != nil || !windows.EqualSid(user.User.Sid, ourSID) {
		_ = windows.CloseHandle(process)
		return 0, fmt.Errorf("client does not belong to the current user")
	}
	return process, nil
}

func processStarted(process windows.Handle) uint64 {
	var created, exited, kernel, user windows.Filetime
	if windows.GetProcessTimes(process, &created, &exited, &kernel, &user) != nil {
		return 0
	}
	return uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime)
}

func clientFromProcess(pid uint32) clientInfo {
	process, err := ownProcess(pid)
	if err != nil {
		return clientInfo{}
	}
	defer func() { _ = windows.CloseHandle(process) }()
	path := make([]uint16, 32768)
	length := uint32(len(path))
	if windows.QueryFullProcessImageName(process, 0, &path[0], &length) != nil || length == 0 {
		return clientInfo{}
	}
	name := filepath.Base(windows.UTF16ToString(path[:length]))
	client := clientInfo{pid: pid, name: name, started: processStarted(process)}
	// Read arguments only for recognized SSH clients. Never retain, log or
	// display a full command line, which may contain passwords or tokens.
	switch strings.ToLower(name) {
	case "putty.exe", "plink.exe", "tortoisegitplink.exe", "ssh.exe":
		if commandLine := processCommandLine(process); commandLine != "" {
			args, err := windows.DecomposeCommandLine(commandLine)
			if err == nil && len(args) > 1 {
				client.target = parseClientTarget(name, args[1:])
				if client.target.session != "" {
					client.target = resolvePuttySession(client.target)
				}
			}
		}
	}
	return client
}

// ProcessCommandLineInformation is best effort: Windows documents that this
// native API can change. Unsupported, denied or structurally invalid replies
// simply leave the target unknown; never inspect a remote process's PEB.
func processCommandLine(process windows.Handle) string {
	if clientNtQueryProcess.Find() != nil {
		return ""
	}
	var required uint32
	clientNtQueryProcess.Call(uintptr(process), uintptr(windows.ProcessCommandLineInformation), 0, 0, uintptr(unsafe.Pointer(&required)))
	if required < uint32(unsafe.Sizeof(windows.NTUnicodeString{})) || required > 128*1024 {
		return ""
	}
	buffer := make([]byte, required)
	status, _, _ := clientNtQueryProcess.Call(uintptr(process), uintptr(windows.ProcessCommandLineInformation), uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), uintptr(unsafe.Pointer(&required)))
	if status != 0 {
		return ""
	}
	value := (*windows.NTUnicodeString)(unsafe.Pointer(&buffer[0]))
	start, ptr := uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(value.Buffer))
	if value.Length%2 != 0 || value.Length > value.MaximumLength || ptr < start || ptr-start > uintptr(len(buffer)) || uintptr(value.Length) > uintptr(len(buffer))-(ptr-start) {
		return ""
	}
	text := string(utf16.Decode(unsafe.Slice(value.Buffer, int(value.Length)/2)))
	runtime.KeepAlive(buffer)
	return text
}

func parseClientTarget(app string, args []string) connectionTarget {
	ssh := strings.EqualFold(app, "ssh.exe")
	puttyGUI := strings.EqualFold(app, "putty.exe")
	if !ssh && !strings.EqualFold(app, "putty.exe") && !strings.EqualFold(app, "plink.exe") && !strings.EqualFold(app, "tortoisegitplink.exe") {
		return connectionTarget{}
	}
	target := connectionTarget{source: "inferred client arguments"}
	hasDestination := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			if i+1 < len(args) {
				parseDestination(&target, args[i+1])
			}
			return target
		}
		if !strings.HasPrefix(arg, "-") {
			if hasDestination {
				return connectionTarget{}
			}
			parseDestination(&target, arg)
			hasDestination = true
			// PuTTY's GUI also accepts options after the hostname. Plink and
			// ssh may put a remote command here; never parse its arguments.
			if puttyGUI {
				continue
			}
			return target
		}
		option, attached := arg, ""
		if ssh && len(arg) > 2 && strings.ContainsRune("lp", rune(arg[1])) {
			option, attached = arg[:2], arg[2:]
		}
		if ssh && len(arg) > 2 && strings.Trim(arg[1:], "v") == "" {
			continue
		}
		noValue := " -ssh -2 -4 -6 -batch -agent -noagent -A -a -C -N -T -t -v -x -X -share -noshare -no-antispoof "
		if ssh {
			noValue = " -4 -6 -A -a -C -f -G -g -K -k -M -N -n -q -s -T -t -V -v -X -x -Y -y "
		}
		if strings.Contains(noValue, " "+option+" ") {
			continue
		}
		valueFlags := " -l -P -load -pw -pwfile -i -m -L -R -D -nc -proxycmd -hostkey -loghost -sercfg -sessionlog -sshlog -sshrawlog "
		if ssh {
			valueFlags = " -B -b -c -D -E -e -F -I -i -J -L -l -m -O -o -P -p -Q -R -S -W -w "
		}
		if !strings.Contains(valueFlags, " "+option+" ") {
			return connectionTarget{}
		}
		value := attached
		if value == "" {
			i++
			if i >= len(args) {
				return connectionTarget{}
			}
			value = args[i]
		}
		switch {
		case option == "-l":
			target.user = safeTargetField(value)
		case (ssh && option == "-p") || (!ssh && option == "-P"):
			port, err := strconv.ParseUint(value, 10, 16)
			if err != nil || port == 0 {
				return connectionTarget{}
			}
			target.port = uint16(port)
		case !ssh && option == "-load":
			target.session = value
		case ssh && option == "-o":
			parts := strings.FieldsFunc(value, func(r rune) bool { return r == '=' || unicode.IsSpace(r) })
			if len(parts) == 2 {
				switch strings.ToLower(parts[0]) {
				case "user":
					target.user = safeTargetField(parts[1])
				case "hostname":
					target.host = safeHost(parts[1])
				case "port":
					port, err := strconv.ParseUint(parts[1], 10, 16)
					if err != nil || port == 0 {
						return connectionTarget{}
					}
					target.port = uint16(port)
				}
			}
		}
	}
	return target
}

func parseDestination(target *connectionTarget, value string) {
	if strings.HasPrefix(strings.ToLower(value), "ssh://") {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Hostname() == "" || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
			return
		}
		if parsed.User != nil {
			if _, hasPassword := parsed.User.Password(); hasPassword {
				return
			}
			if target.user == "" {
				target.user = safeTargetField(parsed.User.Username())
			}
		}
		if target.host == "" {
			target.host = safeHost(parsed.Hostname())
		}
		if portString := parsed.Port(); portString != "" {
			port, err := strconv.ParseUint(portString, 10, 16)
			if err != nil || port == 0 {
				target.host = ""
				return
			}
			if target.port == 0 {
				target.port = uint16(port)
			}
		}
		return
	}
	if at := strings.LastIndexByte(value, '@'); at >= 0 {
		if target.user == "" {
			target.user = safeTargetField(value[:at])
		}
		value = value[at+1:]
	}
	if target.host == "" {
		target.host = safeHost(strings.Trim(value, "[]"))
	}
}

func safeTargetField(value string) string {
	if value == "" || len(value) > 253 {
		return ""
	}
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return ""
		}
	}
	return value
}

func safeHost(host string) string {
	if safeTargetField(host) == "" || strings.ContainsAny(host, "/\\@\"'") || strings.HasPrefix(host, "-") {
		return ""
	}
	if strings.Contains(host, ":") && net.ParseIP(strings.Split(host, "%")[0]) == nil {
		return ""
	}
	return host
}

func resolvePuttySession(target connectionTarget) connectionTarget {
	key, err := registry.OpenKey(registry.CURRENT_USER, `Software\SimonTatham\PuTTY\Sessions`, registry.READ)
	if err != nil {
		return target
	}
	defer func() { _ = key.Close() }()
	names, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return target
	}
	for _, name := range names {
		decoded, err := url.PathUnescape(name)
		if err != nil || decoded != target.session {
			continue
		}
		session, err := registry.OpenKey(key, name, registry.QUERY_VALUE)
		if err != nil {
			return target
		}
		defer func() { _ = session.Close() }()
		protocol, _, err := session.GetStringValue("Protocol")
		if err == nil && protocol != "ssh" {
			return connectionTarget{}
		}
		if target.host == "" {
			host, _, _ := session.GetStringValue("HostName")
			target.host = safeHost(host)
		}
		if target.user == "" {
			user, _, _ := session.GetStringValue("UserName")
			target.user = safeTargetField(user)
		}
		if target.port == 0 {
			port, _, err := session.GetIntegerValue("PortNumber")
			if err == nil && port > 0 && port <= 65535 {
				target.port = uint16(port)
			}
		}
		target.source = "inferred PuTTY session"
		return target
	}
	return target
}

func (p *Pageant) notifySigning(request, response []byte, client clientInfo) {
	sign, ok := openssh.ParseSignRequest(request)
	if !ok || p.state == nil || p.state.desktop == nil {
		return
	}
	target := client.target
	// A generic signature can be Git signing or another operation. Do not
	// label unrelated sockets or an SSH client's arguments as its destination.
	if sign.Username != "" {
		target.user = sign.Username
		if target.host == "" && client.pid != 0 && client.started != 0 {
			process, err := ownProcess(client.pid)
			if err == nil {
				if processStarted(process) == client.started {
					if inferred, ok := uniqueTCPTarget(client.pid); ok {
						target.host, target.port, target.source = inferred.host, inferred.port, inferred.source
					}
				}
				_ = windows.CloseHandle(process)
			}
		}
	} else {
		target = connectionTarget{}
	}
	title, body := signingNotice(sign, response, client, target)
	p.state.desktop.notify(title, body)
}

func signingNotice(sign openssh.SignRequest, response []byte, client clientInfo, target connectionTarget) (string, string) {
	title := "SSH key request failed"
	if openssh.ValidateResponse(response) == nil && response[4] == 14 {
		title = "SSH key used"
	}
	app := "Application unavailable"
	if client.name != "" {
		app = fmt.Sprintf("%s (PID %d)", client.name, client.pid)
		if client.inferred {
			app += " [inferred from mapping]"
		}
	}
	where := "Target unavailable"
	if target.host != "" {
		host := target.host
		if target.port != 0 && target.port != 22 {
			host = net.JoinHostPort(host, strconv.Itoa(int(target.port)))
		} else if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
		if target.user != "" {
			host = target.user + "@" + host
		}
		where = host
		if target.source != "" {
			where += " [" + target.source + "]"
		}
	} else if sign.Username != "" {
		where = sign.Username + "@unknown host"
	}
	return title, app + "\n" + where + "\n" + sign.Fingerprint
}

func uniqueTCPTarget(pid uint32) (connectionTarget, bool) {
	all := make(map[string]connectionTarget)
	for _, family := range []uint32{windows.AF_INET, windows.AF_INET6} {
		entries, ok := processTCPTargets(pid, family)
		if !ok {
			return connectionTarget{}, false
		}
		for _, entry := range entries {
			all[net.JoinHostPort(entry.host, strconv.Itoa(int(entry.port)))] = entry
		}
	}
	if len(all) != 1 {
		return connectionTarget{}, false
	}
	for _, target := range all {
		return target, true
	}
	return connectionTarget{}, false
}

func processTCPTargets(pid, family uint32) ([]connectionTarget, bool) {
	const maxTableBytes = 16 * 1024 * 1024
	var size uint32
	result, _, _ := clientGetTCPTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, uintptr(family), 5, 0) // TCP_TABLE_OWNER_PID_ALL
	if result != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) || size < 4 || size > maxTableBytes {
		return nil, false
	}
	for attempt := 0; attempt < 3; attempt++ {
		buffer := make([]byte, size)
		result, _, _ = clientGetTCPTable.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)), 0, uintptr(family), 5, 0)
		if result == uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
			if size < 4 || size > maxTableBytes {
				return nil, false
			}
			continue
		}
		if result != 0 {
			return nil, false
		}
		return parseTCPTable(buffer, pid, family)
	}
	return nil, false
}

func parseTCPTable(buffer []byte, pid, family uint32) ([]connectionTarget, bool) {
	rowSize, stateOffset, pidOffset := 24, 0, 20
	if family == windows.AF_INET6 {
		rowSize, stateOffset, pidOffset = 56, 48, 52
	} else if family != windows.AF_INET {
		return nil, false
	}
	if len(buffer) < 4 {
		return nil, false
	}
	count := binary.LittleEndian.Uint32(buffer)
	if uint64(count) > uint64((len(buffer)-4)/rowSize) {
		return nil, false
	}
	var result []connectionTarget
	for i := uint32(0); i < count; i++ {
		row := buffer[4+int(i)*rowSize : 4+(int(i)+1)*rowSize]
		if binary.LittleEndian.Uint32(row[stateOffset:]) != 5 || binary.LittleEndian.Uint32(row[pidOffset:]) != pid {
			continue
		} // ESTABLISHED
		target := connectionTarget{source: "inferred network endpoint"}
		if family == windows.AF_INET {
			target.host = net.IP(row[12:16]).String()
			target.port = binary.BigEndian.Uint16(row[16:18])
		} else {
			target.host = net.IP(row[24:40]).String()
			target.port = binary.BigEndian.Uint16(row[44:46])
			if scope := binary.LittleEndian.Uint32(row[40:44]); scope != 0 {
				target.host += "%" + strconv.FormatUint(uint64(scope), 10)
			}
		}
		if target.port != 0 {
			result = append(result, target)
		}
	}
	return result, true
}
