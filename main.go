package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"syscall"
	"unsafe"
)

const (
	HKEY_LOCAL_MACHINE = 0x80000002

	KEY_QUERY_VALUE = 0x0001

	REG_DWORD = 4
	REG_SZ    = 1

	ERROR_SUCCESS = 0
)

var (
	advapi32 = syscall.NewLazyDLL("advapi32.dll")

	procRegConnectRegistryW = advapi32.NewProc("RegConnectRegistryW")
	procRegOpenKeyExW       = advapi32.NewProc("RegOpenKeyExW")
	procRegQueryValueExW    = advapi32.NewProc("RegQueryValueExW")
	procRegCloseKey         = advapi32.NewProc("RegCloseKey")
)

func utf16Ptr(s string) *uint16 {
	p, err := syscall.UTF16PtrFromString(s)
	if err != nil {
		panic(err)
	}
	return p
}

func regConnectRegistry(host string) (syscall.Handle, error) {
	var remoteKey syscall.Handle

	// RegConnectRegistryW expects the computer name as:
	// \\SERVER01
	r, _, _ := procRegConnectRegistryW.Call(
		uintptr(unsafe.Pointer(utf16Ptr(host))),
		uintptr(HKEY_LOCAL_MACHINE),
		uintptr(unsafe.Pointer(&remoteKey)),
	)

	if r != ERROR_SUCCESS {
		return 0, syscall.Errno(r)
	}

	return remoteKey, nil
}

func regOpenKey(root syscall.Handle, subKey string) (syscall.Handle, error) {
	var key syscall.Handle

	r, _, _ := procRegOpenKeyExW.Call(
		uintptr(root),
		uintptr(unsafe.Pointer(utf16Ptr(subKey))),
		0,
		KEY_QUERY_VALUE,
		uintptr(unsafe.Pointer(&key)),
	)

	if r != ERROR_SUCCESS {
		return 0, syscall.Errno(r)
	}

	return key, nil
}

func regQueryDWORD(key syscall.Handle, name string) (uint32, error) {
	var (
		dataType uint32
		data     uint32
		dataSize uint32 = 4
	)

	r, _, _ := procRegQueryValueExW.Call(
		uintptr(key),
		uintptr(unsafe.Pointer(utf16Ptr(name))),
		0,
		uintptr(unsafe.Pointer(&dataType)),
		uintptr(unsafe.Pointer(&data)),
		uintptr(unsafe.Pointer(&dataSize)),
	)

	if r != ERROR_SUCCESS {
		return 0, syscall.Errno(r)
	}

	if dataType != REG_DWORD {
		return 0, fmt.Errorf(
			"registry value %q has unexpected type %d",
			name,
			dataType,
		)
	}

	return data, nil
}

func regQueryString(key syscall.Handle, name string) (string, error) {
	var (
		dataType uint32
		dataSize uint32
	)

	// to get buffer size
	r, _, _ := procRegQueryValueExW.Call(
		uintptr(key),
		uintptr(unsafe.Pointer(utf16Ptr(name))),
		0,
		uintptr(unsafe.Pointer(&dataType)),
		0,
		uintptr(unsafe.Pointer(&dataSize)),
	)

	if r != ERROR_SUCCESS {
		return "", syscall.Errno(r)
	}

	if dataType != REG_SZ {
		return "", fmt.Errorf(
			"registry value %q has unexpected type %d",
			name,
			dataType,
		)
	}

	buf := make([]uint16, (dataSize+1)/2)

	r, _, _ = procRegQueryValueExW.Call(
		uintptr(key),
		uintptr(unsafe.Pointer(utf16Ptr(name))),
		0,
		uintptr(unsafe.Pointer(&dataType)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&dataSize)),
	)

	if r != ERROR_SUCCESS {
		return "", syscall.Errno(r)
	}

	return syscall.UTF16ToString(buf), nil
}

func closeKey(key syscall.Handle) {
	if key != 0 {
		procRegCloseKey.Call(uintptr(key))
	}
}

type WindowsVersion struct {
	Major uint32
	Minor uint32
	Build string
	UBR   uint32
}

func queryRemoteWindowsVersion(host string) (*WindowsVersion, error) {
	remoteHKLM, err := regConnectRegistry(host)
	if err != nil {
		return nil, fmt.Errorf("RegConnectRegistryW: %w", err)
	}
	defer closeKey(remoteHKLM)

	const subKey = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`

	key, err := regOpenKey(remoteHKLM, subKey)
	if err != nil {
		return nil, fmt.Errorf("RegOpenKeyExW: %w", err)
	}
	defer closeKey(key)

	major, err := regQueryDWORD(key, "CurrentMajorVersionNumber")
	if err != nil {
		return nil, fmt.Errorf("query Major: %w", err)
	}

	minor, err := regQueryDWORD(key, "CurrentMinorVersionNumber")
	if err != nil {
		return nil, fmt.Errorf("query Minor: %w", err)
	}

	build, err := regQueryString(key, "CurrentBuildNumber")
	if err != nil {
		return nil, fmt.Errorf("query Build: %w", err)
	}

	ubr, err := regQueryDWORD(key, "UBR")
	if err != nil {
		return nil, fmt.Errorf("query UBR: %w", err)
	}

	return &WindowsVersion{
		Major: major,
		Minor: minor,
		Build: build,
		UBR:   ubr,
	}, nil
}

type patchKey struct {
	major, minor, build int
}

type cvePatch struct {
	alias   string
	patches map[patchKey]int
}

var cvePatches = map[string]cvePatch{
	"CVE-2025-33073 NTLM reflection": {
		patches: map[patchKey]int{
			{10, 0, 10240}: 21034,
			{10, 0, 14393}: 8148,
			{10, 0, 17763}: 7434,
			{10, 0, 19044}: 5965,
			{10, 0, 20348}: 3807,
			{10, 0, 22621}: 5472,
			{10, 0, 25398}: 1665,
			{10, 0, 26100}: 4270,
		},
	},
	"CVE-2025-58726 Ghost SPN": {
		patches: map[patchKey]int{
			{6, 0, 6003}:   23571,
			{6, 1, 7601}:   27974,
			{6, 2, 9200}:   25722,
			{6, 3, 9600}:   22824,
			{10, 0, 10240}: 21161,
			{10, 0, 14393}: 8519,
			{10, 0, 17763}: 7919,
			{10, 0, 19044}: 6456,
			{10, 0, 20348}: 4294,
			{10, 0, 22621}: 6060,
			{10, 0, 25398}: 1913,
			{10, 0, 26100}: 6899,
			{10, 0, 26200}: 6899,
		},
	},
	"CVE-2025-54918 NTLM MIC Bypass": {
		patches: map[patchKey]int{
			{6, 0, 6003}:   23529,
			{6, 1, 7601}:   27929,
			{6, 2, 9200}:   25675,
			{6, 3, 9600}:   22774,
			{10, 0, 10240}: 21128,
			{10, 0, 14393}: 8422,
			{10, 0, 17763}: 7792,
			{10, 0, 19044}: 6332,
			{10, 0, 20348}: 4171,
			{10, 0, 22621}: 5909,
			{10, 0, 22631}: 5909,
			{10, 0, 26100}: 6508,
		},
	},
	"CVE-2025-53779 BadSuccessor": {
		patches: map[patchKey]int{
			{10, 0, 26100}: 4851,
		},
	},
	"CVE-2024-49019 ESC15 / EKUwu": {
		patches: map[patchKey]int{
			{6, 0, 6003}:   22966,
			{6, 1, 7601}:   27415,
			{6, 2, 9200}:   25165,
			{6, 3, 9600}:   22267,
			{10, 0, 14393}: 7515,
			{10, 0, 17763}: 6532,
			{10, 0, 20348}: 2849,
			{10, 0, 25398}: 1251,
			{10, 0, 26100}: 2314,
		},
	},
	"CVE-2026-54121 Certighost": {
		patches: map[patchKey]int{
			{6, 2, 9200}:   26226,
			{6, 3, 9600}:   23291,
			{10, 0, 14393}: 9339,
			{10, 0, 17763}: 9020,
			{10, 0, 20348}: 5386,
			{10, 0, 26100}: 33158,
		},
	},
	"CVE-2026-27912 ResetNightmare": {
		patches: map[patchKey]int{
			{6, 2, 9200}:   26026,
			{6, 3, 9600}:   23132,
			{10, 0, 14393}: 9060,
			{10, 0, 17763}: 8644,
			{10, 0, 20348}: 5020,
			{10, 0, 25398}: 2274,
			{10, 0, 26100}: 32690,
		},
	},
}

var OsStringName = map[patchKey]string {
	{6, 0, 6003}:   "Windows Server 2008 SP2",
	{6, 1, 7601}:   "Windows Server 2008 R2 SP1",
	{6, 2, 9200}:   "Windows Server 2012",
	{6, 3, 9600}:   "Windows Server 2012 R2",
	{10, 0, 10240}: "Windows 10 1507",
	{10, 0, 14393}: "Windows Server 2016",
	{10, 0, 17763}: "Windows Server 2019 / Win10 1809",
	{10, 0, 19044}: "Windows 10 21H2",
	{10, 0, 20348}: "Windows Server 2022",
	{10, 0, 22621}: "Windows 11 22H2",
	{10, 0, 22631}: "Windows 11 23H2",
	{10, 0, 26100}: "Windows Server 2025 / Win11 24H2",
}


func printVulnerable(hostname string, key patchKey, ubr int) {

	for cve, patch := range cvePatches {
		minUBR, ok := patch.patches[key]
		if !ok {
			// This OS build isn't represented in our patch data.
			continue
		}

		if ubr < minUBR {
			fmt.Printf("[!] %s may be vulnerable to %s\n", hostname, cve)
		}
	}
}

func test(hostname string) {
	host := `\\` + hostname

	fmt.Printf("[*] Trying to enumerate Windows versions on %s\n", host)

	version, err := queryRemoteWindowsVersion(host)
	if err != nil {
		fmt.Printf("[-] Error: %v\n", err)
		fmt.Println()
		return
	}

	fmt.Printf(
		"[*] %s Windows version: Major: %d Minor: %d Build: %s Update Build Revision: %d\n",
		host,
		version.Major,
		version.Minor,
		version.Build,
		version.UBR,
	)
	buildInt, _ := strconv.Atoi(version.Build)

	key := patchKey{int(version.Major), int(version.Minor), buildInt}
	osName, ok := OsStringName[key]
	if !ok{
		fmt.Println("Unknown OS")
	} else {
		fmt.Printf("[*] %s detected OS: %s\n", host, osName)
	}

	printVulnerable(host, key, int(version.UBR))
	fmt.Println()
}

func main() {
	if len(os.Args) == 1 {
		fmt.Println("Usage:")
		fmt.Printf("  %s <file>\n\n", os.Args[0])
		fmt.Println("The file should contain one host per line to test.")
		return
	}

	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Error: expected exactly one argument.\n")
		fmt.Printf("Usage: %s <file>\n", os.Args[0])
		os.Exit(1)
	}

	filename := os.Args[1]

	file, err := os.Open(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening file %q: %v\n", filename, err)
		os.Exit(1)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		host := scanner.Text()

		if host == "" {
			continue
		}

		test(host)
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file %q: %v\n", filename, err)
		os.Exit(1)
	}
}
