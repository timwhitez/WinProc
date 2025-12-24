package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// 1. DLL and Procedure Definitions
var (
	modkernel32 = syscall.NewLazyDLL("kernel32.dll")
	modadvapi32 = syscall.NewLazyDLL("advapi32.dll")
	modntdll    = syscall.NewLazyDLL("ntdll.dll")
	modpsapi    = syscall.NewLazyDLL("psapi.dll")

	procCreateToolhelp32Snapshot = modkernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32First           = modkernel32.NewProc("Process32FirstW")
	procProcess32Next            = modkernel32.NewProc("Process32NextW")
	procOpenProcess              = modkernel32.NewProc("OpenProcess")
	procCloseHandle              = modkernel32.NewProc("CloseHandle")
	procGetCurrentProcessId      = modkernel32.NewProc("GetCurrentProcessId")
	procDuplicateHandle          = modkernel32.NewProc("DuplicateHandle")
	procGetProcessId             = modkernel32.NewProc("GetProcessId")
	procQueryFullProcessImageNameW = modkernel32.NewProc("QueryFullProcessImageNameW")
	procReadProcessMemory          = modkernel32.NewProc("ReadProcessMemory")

	procOpenProcessToken     = modadvapi32.NewProc("OpenProcessToken")
	procGetTokenInformation  = modadvapi32.NewProc("GetTokenInformation")
	procLookupPrivilegeNameW = modadvapi32.NewProc("LookupPrivilegeNameW")

	procNtQuerySystemInformation  = modntdll.NewProc("NtQuerySystemInformation")
	procNtQueryInformationProcess = modntdll.NewProc("NtQueryInformationProcess")

	procEnumProcessModules   = modpsapi.NewProc("EnumProcessModules")
	procGetModuleFileNameExW = modpsapi.NewProc("GetModuleFileNameExW")
)

// 2. Constants
const (
	// Snapshot flags
	TH32CS_SNAPPROCESS = 0x00000002

	// Process access rights
	PROCESS_TERMINATE                 = 0x0001
	PROCESS_CREATE_THREAD             = 0x0002
	PROCESS_VM_OPERATION              = 0x0008
	PROCESS_VM_READ                   = 0x0010
	PROCESS_VM_WRITE                  = 0x0020
	PROCESS_DUP_HANDLE                = 0x0040
	PROCESS_CREATE_PROCESS            = 0x0080
	PROCESS_SET_QUOTA                 = 0x0100
	PROCESS_SET_INFORMATION           = 0x0200
	PROCESS_QUERY_INFORMATION         = 0x0400
	PROCESS_SUSPEND_RESUME            = 0x0800
	PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
	PROCESS_ALL_ACCESS                = 0x1F0FFF

	// Token access rights
	TOKEN_QUERY = 0x0008

	// Token Information Class
	TokenPrivileges     = 3
	TokenIntegrityLevel = 25

	// Max Path for file names
	MAX_PATH = 260

	// System Information Class
	SystemExtendedHandleInformation = 64

	// NTSTATUS
	STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
	STATUS_SUCCESS              = 0x00000000

	// DuplicateHandle Flags
	DUPLICATE_SAME_ACCESS = 0x00000002
	
	// Process Info Class
	ProcessBasicInformation = 0

	// Generic Access Rights
	DELETE       = 0x00010000
	READ_CONTROL = 0x00020000
	WRITE_DAC    = 0x00040000
	WRITE_OWNER  = 0x00080000
	SYNCHRONIZE  = 0x00100000
)

// 3. Integrity Level Constants (RIDs)
const (
	SECURITY_MANDATORY_UNTRUSTED_RID = 0x00000000
	SECURITY_MANDATORY_LOW_RID       = 0x00001000
	SECURITY_MANDATORY_MEDIUM_RID    = 0x00002000
	SECURITY_MANDATORY_HIGH_RID      = 0x00003000
	SECURITY_MANDATORY_SYSTEM_RID    = 0x00004000
)

// 4. Structures

// PROCESSENTRY32W (Unicode)
type PROCESSENTRY32 struct {
	Size            uint32
	CntUsage        uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	CntThreads      uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [MAX_PATH]uint16
}

// SID_AND_ATTRIBUTES
type SID_AND_ATTRIBUTES struct {
	Sid        uintptr // Pointer to the SID structure
	Attributes uint32
}

// TOKEN_MANDATORY_LABEL
type TOKEN_MANDATORY_LABEL struct {
	Label SID_AND_ATTRIBUTES
}

// SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
type SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX struct {
	Object                uintptr // PVOID
	UniqueProcessId       uintptr // ULONG_PTR
	HandleValue           uintptr // ULONG_PTR
	GrantedAccess         uint32  // ULONG
	CreatorBackTraceIndex uint16  // USHORT
	ObjectTypeIndex       uint16  // USHORT
	HandleAttributes      uint32  // ULONG
	Reserved              uint32  // ULONG
}

// SYSTEM_HANDLE_INFORMATION_EX
type SYSTEM_HANDLE_INFORMATION_EX struct {
	NumberOfHandles uintptr
	Reserved        uintptr
	// Handles [1]SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
}

type LUID struct {
	LowPart  uint32
	HighPart int32
}

type LUID_AND_ATTRIBUTES struct {
	Luid       LUID
	Attributes uint32
}

type TOKEN_PRIVILEGES struct {
	PrivilegeCount uint32
	Privileges     [1]LUID_AND_ATTRIBUTES // Variable length
}

type IntegrityInfo struct {
	Name string
	RID  uint32
}

type UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        uintptr
}

type PROCESS_BASIC_INFORMATION struct {
	ExitStatus                   uintptr
	PebBaseAddress               uintptr
	AffinityMask                 uintptr
	BasePriority                 int32
	UniqueProcessId              uintptr
	InheritedFromUniqueProcessId uintptr
}

// Command Line Flags
var (
	scanMode      string
	pidArg        int
	dllScanArg    string
)

func usage() {
	fmt.Fprintf(os.Stderr, "\nWindows Process Security Scanner (winproc)\n\n")
	fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
	
	fmt.Fprintf(os.Stderr, "Core Commands:\n")
	fmt.Fprintf(os.Stderr, "  -scan <mode>      Select scan mode (Required for scanning)\n")
	fmt.Fprintf(os.Stderr, "                    Modes:\n")
	fmt.Fprintf(os.Stderr, "                      info      : Show process image path and command line\n")
	fmt.Fprintf(os.Stderr, "                      vulnpath  : Scan for Unquoted Service Paths (Config Issues)\n")
	fmt.Fprintf(os.Stderr, "                      dlls      : Scan for DLL Hijacking (writable loaded DLLs)\n")
	fmt.Fprintf(os.Stderr, "                      handles   : Scan handles HELD BY process (Outbound)\n")
	fmt.Fprintf(os.Stderr, "                      exposed   : Scan handles pointing TO process (Inbound/Exposure)\n")
	fmt.Fprintf(os.Stderr, "                      token     : Scan for dangerous token privileges\n")
	fmt.Fprintf(os.Stderr, "                      lpe       : Scan for PrivEsc opportunities (High integrity procs)\n")
	fmt.Fprintf(os.Stderr, "                      all       : Run ALL scans (Recommended for full audit)\n\n")

	fmt.Fprintf(os.Stderr, "Options:\n")
	fmt.Fprintf(os.Stderr, "  -pid <id>         Target a specific PID (Default: scans all processes)\n\n")
	
	fmt.Fprintf(os.Stderr, "Examples:\n")
	fmt.Fprintf(os.Stderr, "  %s -scan all\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "  %s -scan handles -pid 1234\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "  %s -scan info -pid 1234\n", os.Args[0])
}

func printCurrentProcessState() {
	myPid, _, _ := procGetCurrentProcessId.Call()
	fmt.Println("================================================================================")
	fmt.Printf(">>> CURRENT PROCESS CONTEXT (PID: %d) <<<\n", myPid)
	fmt.Println("================================================================================")

	// 1. Integrity Level
	il, err := getProcessIntegrityLevel(uint32(myPid))
	if err == nil {
		fmt.Printf("Integrity Level : %s (RID: %d)\n", il.Name, il.RID)
	} else {
		fmt.Printf("Integrity Level : <Error: %v>\n", err)
	}

	// 2. Privileges
	hProcess, _, _ := procOpenProcess.Call(uintptr(PROCESS_QUERY_LIMITED_INFORMATION), 0, myPid)
	if hProcess != 0 {
		var hToken uintptr
		ret, _, _ := procOpenProcessToken.Call(hProcess, uintptr(TOKEN_QUERY), uintptr(unsafe.Pointer(&hToken)))
		if ret != 0 {
			privs, err := getTokenPrivileges(hToken)
			if err == nil {
				if len(privs) > 0 {
					fmt.Printf("Enabled Privs   : %s\n", strings.Join(privs, ", "))
				} else {
					fmt.Printf("Enabled Privs   : (None)\n")
				}
			}
			procCloseHandle.Call(hToken)
		}
		procCloseHandle.Call(hProcess)
	}
	fmt.Println("--------------------------------------------------------------------------------\n")
}

func main() {
	flag.Usage = usage
	flag.StringVar(&scanMode, "scan", "", "Scan mode: info, vulnpath, dlls, handles, exposed, token, lpe, all")
	flag.IntVar(&pidArg, "pid", 0, "Target PID (optional)")
	flag.Parse()

	// Scan logic
	if scanMode != "" {
		printCurrentProcessState()

		target := "all"
		if pidArg != 0 {
			target = strconv.Itoa(pidArg)
		}

		switch strings.ToLower(scanMode) {
		case "info":
			runInfo(target)
		case "vulnpath":
			runVulnScan(target)
		case "dlls":
			runDllScan(target)
		case "handles":
			runHandleScan(target)
		case "exposed":
			runExposedScan(target)
		case "token":
			runTokenScan(target)
		case "lpe":
			runLPECheck(target)
		case "all":
			fmt.Println("================================================================================")
			if target == "all" {
				fmt.Println(">>> RUNNING FULL SYSTEM SCAN <<<")
			} else {
				fmt.Printf(">>> RUNNING SCAN FOR PID %s <<<\n", target)
			}
			fmt.Println("================================================================================")
			
			fmt.Println("\n[+] PHASE 1: Basic Information")
			runInfo(target)

			fmt.Println("\n[+] PHASE 2: Privilege Escalation Opportunities (Process Access)")
			runLPECheck(target)
			
			fmt.Println("\n[+] PHASE 3: Configuration Vulnerabilities (Unquoted Paths)")
			runVulnScan(target)
			
			fmt.Println("\n[+] PHASE 4: Handle Leaks (Outbound - Held By Target)")
			runHandleScan(target)

			fmt.Println("\n[+] PHASE 5: Handle Exposure (Inbound - Pointing To Target)")
			runExposedScan(target)
			
			fmt.Println("\n[+] PHASE 6: Token Privileges")
			runTokenScan(target)
			
			fmt.Println("\n[+] PHASE 7: DLL Hijacking Risks")
			runDllScan(target)
			
			fmt.Println("\n================================================================================")
			fmt.Println(">>> SCAN COMPLETE <<<")
			fmt.Println("================================================================================")

		default:
			fmt.Printf("Unknown scan mode: %s\n", scanMode)
			usage()
		}
		return
	}

	// Default behavior if just PID provided as arg
	args := flag.Args()
	if len(args) > 0 {
		pidStr := args[0]
		pid, err := strconv.Atoi(pidStr)
		if err == nil {
			checkSinglePid(uint32(pid))
			return
		}
	}

	usage()
}

// --- Original Functionality ---

func checkSinglePid(pid uint32) {
	fmt.Printf("Checking permissions for PID: %d\n\n", pid)

	perms := []struct {
		Name  string
		Value uint32
	}{
		{"PROCESS_ALL_ACCESS", PROCESS_ALL_ACCESS},
		{"PROCESS_VM_OPERATION", PROCESS_VM_OPERATION},
		{"PROCESS_VM_WRITE", PROCESS_VM_WRITE},
		{"PROCESS_CREATE_THREAD", PROCESS_CREATE_THREAD},
		{"PROCESS_QUERY_LIMITED_INFORMATION", PROCESS_QUERY_LIMITED_INFORMATION},
		{"PROCESS_VM_READ", PROCESS_VM_READ},
		{"PROCESS_TERMINATE", PROCESS_TERMINATE},
		{"PROCESS_QUERY_INFORMATION", PROCESS_QUERY_INFORMATION},
	}

	for _, p := range perms {
		checkPermission(pid, p.Name, p.Value)
	}
}

func checkPermission(pid uint32, name string, access uint32) bool {
	h, _, _ := procOpenProcess.Call(uintptr(access), 0, uintptr(pid))
	if h != 0 {
		fmt.Printf("[+] Success: %s (0x%X)\n", name, access)
		procCloseHandle.Call(h)
		return true
	} else {
		fmt.Printf("[-] Failed:  %s (0x%X)\n", name, access)
		return false
	}
}

// --- Info Functionality ---

func runInfo(target string) {
	fmt.Printf("[*] Starting Info Scan (Target: %s)...\n", target)

	if target != "all" {
		pid, err := strconv.Atoi(target)
		if err != nil {
			fmt.Printf("[-] Invalid PID: %s\n", target)
			return
		}
		printProcessInfo(uint32(pid))
		return
	}

	// Scan all
	hSnap, _, _ := procCreateToolhelp32Snapshot.Call(uintptr(TH32CS_SNAPPROCESS), 0)
	if int32(hSnap) == -1 {
		fmt.Println("[-] Failed to create snapshot")
		return
	}
	defer procCloseHandle.Call(hSnap)

	var pe32 PROCESSENTRY32
	pe32.Size = uint32(unsafe.Sizeof(pe32))

	ret, _, _ := procProcess32First.Call(hSnap, uintptr(unsafe.Pointer(&pe32)))
	for ret != 0 {
		pid := pe32.ProcessID
		if pid != 0 {
			printProcessInfo(pid)
			fmt.Println("---")
		}
		ret, _, _ = procProcess32Next.Call(hSnap, uintptr(unsafe.Pointer(&pe32)))
	}
}

func printProcessInfo(pid uint32) {
	fmt.Printf("PID: %d\n", pid)

	// 1. Image Path
	hProcess, _, _ := procOpenProcess.Call(uintptr(PROCESS_QUERY_LIMITED_INFORMATION), 0, uintptr(pid))
	if hProcess != 0 {
		pathBuf := make([]uint16, MAX_PATH)
		size := uint32(MAX_PATH)
		r, _, _ := procQueryFullProcessImageNameW.Call(hProcess, 0, uintptr(unsafe.Pointer(&pathBuf[0])), uintptr(unsafe.Pointer(&size)))
		if r != 0 {
			fmt.Printf("  Image Path: %s\n", syscall.UTF16ToString(pathBuf[:size]))
		} else {
			fmt.Printf("  Image Path: <Error QueryFullProcessImageNameW>\n")
		}
		procCloseHandle.Call(hProcess)
	} else {
		fmt.Printf("  Image Path: <Access Denied - OpenProcess>\n")
	}

	// 2. Command Line
	cmdLine, err := getCommandLine(pid)
	if err != nil {
		fmt.Printf("  Command Line: <%v>\n", err)
	} else {
		fmt.Printf("  Command Line: %s\n", cmdLine)
	}
}

func getCommandLine(pid uint32) (string, error) {
	// Need PROCESS_VM_READ and PROCESS_QUERY_INFORMATION
	hProcess, _, _ := procOpenProcess.Call(uintptr(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ), 0, uintptr(pid))
	if hProcess == 0 {
		return "", fmt.Errorf("Access Denied (Needs PROCESS_VM_READ)")
	}
	defer procCloseHandle.Call(hProcess)

	var pbi PROCESS_BASIC_INFORMATION
	var returnLen uint32
	status, _, _ := procNtQueryInformationProcess.Call(
		hProcess, 
		uintptr(ProcessBasicInformation), 
		uintptr(unsafe.Pointer(&pbi)), 
		unsafe.Sizeof(pbi), 
		uintptr(unsafe.Pointer(&returnLen)),
	)

	if uint32(status) != STATUS_SUCCESS {
		return "", fmt.Errorf("NtQueryInformationProcess failed: 0x%X", status)
	}

	// Parse PEB to find CommandLine
	// PEB address is in pbi.PebBaseAddress
	// ProcessParameters is at PEB + 0x20 (x64)
	
	var paramsAddr uintptr
	// Assuming 64-bit target here. Offset 0x20 for ProcessParameters
	// Read pointer to ProcessParameters
	ret, _, _ := procReadProcessMemory.Call(
		hProcess,
		pbi.PebBaseAddress + 0x20,
		uintptr(unsafe.Pointer(&paramsAddr)),
		unsafe.Sizeof(paramsAddr),
		0,
	)
	if ret == 0 {
		return "", fmt.Errorf("ReadProcessMemory (PEB) failed")
	}

	// CommandLine is at ProcessParameters + 0x70 (x64)
	// It is a UNICODE_STRING
	var cmdLineStr UNICODE_STRING
	ret, _, _ = procReadProcessMemory.Call(
		hProcess,
		paramsAddr + 0x70,
		uintptr(unsafe.Pointer(&cmdLineStr)),
		unsafe.Sizeof(cmdLineStr),
		0,
	)
	if ret == 0 {
		return "", fmt.Errorf("ReadProcessMemory (Params) failed")
	}

	// Read buffer
	if cmdLineStr.Length == 0 {
		return "", nil
	}

	buf := make([]uint16, cmdLineStr.Length/2)
	ret, _, _ = procReadProcessMemory.Call(
		hProcess,
		cmdLineStr.Buffer,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(cmdLineStr.Length),
		0,
	)
	if ret == 0 {
		return "", fmt.Errorf("ReadProcessMemory (Buffer) failed")
	}

	return syscall.UTF16ToString(buf), nil
}

// --- Vuln Scan Functionality (Cleaned up: Unquoted Paths ONLY) ---

func runVulnScan(target string) {
	fmt.Printf("[*] Starting Vulnerability Scan (Target: %s)...\n", target)
	fmt.Println("[*] Checking for: Unquoted Service Paths")
	fmt.Println("--------------------------------------------------------------------------------")

	// Only scan logic here, handle scan is now separate
	if target != "all" {
		pid, _ := strconv.Atoi(target)
		checkVuln(uint32(pid))
		return
	}

	hSnap, _, _ := procCreateToolhelp32Snapshot.Call(uintptr(TH32CS_SNAPPROCESS), 0)
	if int32(hSnap) == -1 {
		fmt.Println("[-] Failed to create snapshot")
		return
	}
	defer procCloseHandle.Call(hSnap)

	var pe32 PROCESSENTRY32
	pe32.Size = uint32(unsafe.Sizeof(pe32))

	ret, _, _ := procProcess32First.Call(hSnap, uintptr(unsafe.Pointer(&pe32)))
	for ret != 0 {
		pid := pe32.ProcessID
		if pid != 0 {
			checkVuln(pid)
		}
		ret, _, _ = procProcess32Next.Call(hSnap, uintptr(unsafe.Pointer(&pe32)))
	}
	fmt.Println("[*] Vulnerability scan complete.")
}

func checkVuln(pid uint32) {
	// Filter: High/System Integrity Only
	il, err := getProcessIntegrityLevel(pid)
	if err != nil {
		return
	}
	
	// Part 1: Unquoted Service Paths (Only relevant for High/System)
	if il.RID >= SECURITY_MANDATORY_HIGH_RID {
		// Get Path
		fullPath := ""
		hProcess, _, _ := procOpenProcess.Call(uintptr(PROCESS_QUERY_LIMITED_INFORMATION), 0, uintptr(pid))
		if hProcess != 0 {
			pathBuf := make([]uint16, MAX_PATH)
			size := uint32(MAX_PATH)
			r, _, _ := procQueryFullProcessImageNameW.Call(hProcess, 0, uintptr(unsafe.Pointer(&pathBuf[0])), uintptr(unsafe.Pointer(&size)))
			if r != 0 {
				fullPath = syscall.UTF16ToString(pathBuf[:size])
			}
			procCloseHandle.Call(hProcess)
		}
		
		if fullPath != "" {
			cmdLine, err := getCommandLine(pid)
			if err == nil && cmdLine != "" {
				if strings.Contains(fullPath, " ") && !strings.HasPrefix(cmdLine, "\"") && strings.HasPrefix(cmdLine, fullPath) {
					fmt.Printf("[!] UNQUOTED PATH POTENTIAL: PID %d (%s)\n", pid, il.Name)
					fmt.Printf("    Path: %s\n", fullPath)
					fmt.Printf("    Cmd : %s\n", cmdLine)
				}
			}
		}
	}
	// Removed: Part 2 Handle Leak Check (Now handled by -scan handles)
}

// --- DLL Scan Functionality ---

func runDllScan(target string) {
	fmt.Printf("[*] Starting DLL Hijack Scan (Target: %s)...\n", target)
	
	// Inner function to scan a single PID
	scanPid := func(pid uint32, name string) {
		// Filter: High/System Integrity Only (mostly interesting)
		il, err := getProcessIntegrityLevel(pid)
		if err != nil || il.RID < SECURITY_MANDATORY_HIGH_RID {
			// Skip low integrity processes to reduce noise, as we are looking for PRIV ESC
			return
		}

		// Needs QUERY_INFORMATION | VM_READ for EnumProcessModules
		hProcess, _, _ := procOpenProcess.Call(uintptr(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ), 0, uintptr(pid))
		if hProcess == 0 {
			return 
		}
		defer procCloseHandle.Call(hProcess)

		// Enum Modules
		// 1024 modules max
		var modules [1024]uintptr
		var cbNeeded uint32
		
		ret, _, _ := procEnumProcessModules.Call(
			hProcess,
			uintptr(unsafe.Pointer(&modules[0])),
			uintptr(1024 * unsafe.Sizeof(uintptr(0))),
			uintptr(unsafe.Pointer(&cbNeeded)),
		)
		
		if ret == 0 {
			return
		}

		count := int(cbNeeded) / int(unsafe.Sizeof(uintptr(0)))
		if count > 1024 { count = 1024 }

		for i := 0; i < count; i++ {
			hMod := modules[i]
			pathBuf := make([]uint16, MAX_PATH)
			r, _, _ := procGetModuleFileNameExW.Call(hProcess, hMod, uintptr(unsafe.Pointer(&pathBuf[0])), uintptr(MAX_PATH))
			if r > 0 {
				dllPath := syscall.UTF16ToString(pathBuf[:r])
				lowerPath := strings.ToLower(dllPath)
				
				// Skip .exe files (Main executables) to reduce noise in DLL scan
				if strings.HasSuffix(lowerPath, ".exe") {
					continue
				}
				
				// Check for writable paths
				suspicious := false
				if strings.HasPrefix(lowerPath, "c:\\users\\") || 
				   strings.HasPrefix(lowerPath, "c:\\temp\\") || 
				   strings.HasPrefix(lowerPath, "c:\\programdata\\") ||
				   strings.HasPrefix(lowerPath, "c:\\windows\\temp\\") {
					suspicious = true
				}

				if suspicious {
					fmt.Printf("[!] SUSPICIOUS DLL: %s\n", dllPath)
					fmt.Printf("    Process: %s (PID: %d) | Integrity: %s\n", name, pid, il.Name)
				}
			}
		}
	}

	if target != "all" {
		pid, _ := strconv.Atoi(target)
		scanPid(uint32(pid), "<target>")
		return
	}

	// Scan All
	hSnap, _, _ := procCreateToolhelp32Snapshot.Call(uintptr(TH32CS_SNAPPROCESS), 0)
	if int32(hSnap) == -1 {
		fmt.Println("[-] Failed to create snapshot")
		return
	}
	defer procCloseHandle.Call(hSnap)

	var pe32 PROCESSENTRY32
	pe32.Size = uint32(unsafe.Sizeof(pe32))

	ret, _, _ := procProcess32First.Call(hSnap, uintptr(unsafe.Pointer(&pe32)))
	for ret != 0 {
		pid := pe32.ProcessID
		if pid != 0 {
			name := syscall.UTF16ToString(pe32.ExeFile[:])
			scanPid(pid, name)
		}
		ret, _, _ = procProcess32Next.Call(hSnap, uintptr(unsafe.Pointer(&pe32)))
	}
}

// --- LPE Scan Functionality ---

func runLPECheck(target string) {
	myPid, _, _ := procGetCurrentProcessId.Call()
	myIL, err := getProcessIntegrityLevel(uint32(myPid))
	if err != nil {
		fmt.Printf("[-] Failed to get current process integrity level: %v\n", err)
		return
	}
	fmt.Printf("[*] Current Process PID: %d, Integrity Level: %s (RID: %d)\n", myPid, myIL.Name, myIL.RID)
	
	if target != "all" {
		targetPid, err := strconv.Atoi(target)
		if err != nil {
			fmt.Printf("[-] Invalid PID: %s\n", target)
			return
		}
		
		fmt.Printf("[*] Checking LPE opportunities for PID: %d\n", targetPid)
		checkLPETarget(uint32(targetPid), myIL)
		return
	}

	fmt.Println("[*] Scanning for processes with HIGHER integrity level accessible by current user...")
	fmt.Println("--------------------------------------------------------------------------------")

	hSnap, _, _ := procCreateToolhelp32Snapshot.Call(uintptr(TH32CS_SNAPPROCESS), 0)
	if int32(hSnap) == -1 {
		fmt.Println("[-] Failed to create snapshot")
		return
	}
	defer procCloseHandle.Call(hSnap)

	var pe32 PROCESSENTRY32
	pe32.Size = uint32(unsafe.Sizeof(pe32))

	ret, _, _ := procProcess32First.Call(hSnap, uintptr(unsafe.Pointer(&pe32)))
	if ret == 0 {
		fmt.Println("[-] Failed to get first process")
		return
	}

	count := 0
	found := 0

	for {
		pid := pe32.ProcessID
		if pid == 0 || pid == uint32(myPid) {
			ret, _, _ = procProcess32Next.Call(hSnap, uintptr(unsafe.Pointer(&pe32)))
			if ret == 0 {
				break
			}
			count++
			continue
		}

		if checkLPETarget(pid, myIL) {
			found++
		}

		ret, _, _ = procProcess32Next.Call(hSnap, uintptr(unsafe.Pointer(&pe32)))
		if ret == 0 {
			break
		}
		count++
	}
	fmt.Printf("[*] Scan complete. Scanned %d processes. Found %d potentially vulnerable targets.\n", count, found)
}

func checkLPETarget(pid uint32, myIL IntegrityInfo) bool {
	targetIL, err := getProcessIntegrityLevel(pid)
	if err != nil {
		return false
	}

	if targetIL.RID > myIL.RID {
		// Get Name
		name := "<unknown>"
		hProcess, _, _ := procOpenProcess.Call(uintptr(PROCESS_QUERY_LIMITED_INFORMATION), 0, uintptr(pid))
		if hProcess != 0 {
			pathBuf := make([]uint16, MAX_PATH)
			size := uint32(MAX_PATH)
			r, _, _ := procQueryFullProcessImageNameW.Call(hProcess, 0, uintptr(unsafe.Pointer(&pathBuf[0])), uintptr(unsafe.Pointer(&size)))
			if r != 0 {
				path := syscall.UTF16ToString(pathBuf[:size])
				// Just get filename
				parts := strings.Split(path, "\\")
				if len(parts) > 0 {
					name = parts[len(parts)-1]
				}
			}
			procCloseHandle.Call(hProcess)
		}

		var successes []string
		isCritical := false

		permsToCheck := []struct {
			Name string
			Value uint32
			Critical bool
		}{
			{"PROCESS_ALL_ACCESS", PROCESS_ALL_ACCESS, true},
			{"PROCESS_TERMINATE", PROCESS_TERMINATE, true},
			{"PROCESS_CREATE_THREAD", PROCESS_CREATE_THREAD, true},
			{"PROCESS_VM_WRITE", PROCESS_VM_WRITE, true},
			{"PROCESS_VM_OPERATION", PROCESS_VM_OPERATION, true},
			{"PROCESS_QUERY_LIMITED_INFORMATION", PROCESS_QUERY_LIMITED_INFORMATION, false},
		}

		for _, p := range permsToCheck {
			h, _, _ := procOpenProcess.Call(uintptr(p.Value), 0, uintptr(pid))
			if h != 0 {
				successes = append(successes, p.Name)
				if p.Critical {
					isCritical = true
				}
				procCloseHandle.Call(h)
			}
		}

		if len(successes) > 0 {
			prefix := "[+]"
			if isCritical {
				prefix = "[!] LPE POTENTIAL"
			}
			
			fmt.Printf("%s %s (PID: %d) | Target IL: %s\n", prefix, name, pid, targetIL.Name)
			for _, s := range successes {
				fmt.Printf("    -> %s\n", s)
			}
			fmt.Println("")
			if isCritical {
				return true
			}
		}
	}
	return false
}

// --- Handle Scan Functionality ---

func runHandleScan(target string) {
	fmt.Printf("[*] Starting Handle Leak Scan (Target: %s)...\n", target)
	
	// 1. Identify Process Object Type Index
	processTypeIndex, err := getProcessObjectTypeIndex()
	if err != nil {
		fmt.Printf("[-] Failed to identify Process Object Type: %v\n", err)
		return
	}
	fmt.Printf("[+] Identified Process Object Type Index: %d\n", processTypeIndex)

	// 2. Get All System Handles
	fmt.Println("[*] Enumerating system handles (this may take a moment)...")
	handles, err := getSystemHandles()
	if err != nil {
		fmt.Printf("[-] Failed to enumerate handles: %v\n", err)
		return
	}
	fmt.Printf("[*] Found %d total system handles.\n", len(handles))

	// 3. Scan
	found := 0
	
	for _, h := range handles {
		// Filter: Must be Process Type
		if h.ObjectTypeIndex != processTypeIndex {
			continue
		}

		ownerPid := uint32(h.UniqueProcessId)
		
		// Filter: Target
		if target != "all" {
			targetPidInt, _ := strconv.Atoi(target)
			if ownerPid != uint32(targetPidInt) {
				continue
			}
		}

		// Analyze: Owner IL vs Target IL
		ownerIL, err := getProcessIntegrityLevel(ownerPid)
		if err != nil {
			continue // Skip if can't read owner
		}

		// We need to resolve the handle target to know IF it is sensitive
		// This requires DuplicateHandle.
		// We need PROCESS_DUP_HANDLE access to the Owner.
		
		hOwner, _, _ := procOpenProcess.Call(uintptr(PROCESS_DUP_HANDLE), 0, uintptr(ownerPid))
		if hOwner == 0 {
			continue // Can't duplicate from this process
		}

		targetPid, err := getHandleTargetPid(hOwner, h.HandleValue)
		procCloseHandle.Call(hOwner) // Close immediately
		
		if err != nil {
			continue
		}

		// Now check Target IL
		targetIL, err := getProcessIntegrityLevel(targetPid)
		if err != nil {
			continue
		}

		// CONDITION: Owner IL < Target IL AND Handle has Write Access
		// Filter out Low -> Low or Medium -> Medium. We want Lower -> Higher.
		if ownerIL.RID < targetIL.RID {
			// Check Access
			// PROCESS_ALL_ACCESS or WRITE access
			isInteresting := false
			if (h.GrantedAccess & PROCESS_ALL_ACCESS) == PROCESS_ALL_ACCESS {
				isInteresting = true
			} else if (h.GrantedAccess & (PROCESS_VM_WRITE | PROCESS_CREATE_THREAD)) != 0 {
				isInteresting = true
			}

			if isInteresting {
				accessStr := decodeAccessMask(h.GrantedAccess)
				fmt.Printf("[!] LEAKED HANDLE: Owner PID %d (%s) -> Target PID %d (%s)\n", 
					ownerPid, ownerIL.Name, targetPid, targetIL.Name)
				fmt.Printf("    Handle Value: 0x%X | Access: %s\n", h.HandleValue, accessStr)
				found++
			}
		}
	}

	fmt.Printf("[*] Handle scan complete. Found %d interesting leaked handles.\n", found)
}

func getSystemHandles() ([]SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, error) {
	var size uint32 = 1024 * 1024 // 1MB start
	var retLen uint32

	for {
		buf := make([]byte, size)
		status, _, _ := procNtQuerySystemInformation.Call(
			uintptr(SystemExtendedHandleInformation),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(size),
			uintptr(unsafe.Pointer(&retLen)),
		)

		if uint32(status) == STATUS_INFO_LENGTH_MISMATCH {
			if retLen > size {
				size = retLen + (1024 * 1024)
			} else {
				size = size * 2
			}
			continue
		}

		if uint32(status) != STATUS_SUCCESS {
			return nil, fmt.Errorf("NtQuerySystemInformation failed: 0x%X", status)
		}

		var handles []SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
		numberOfHandles := *(*uintptr)(unsafe.Pointer(&buf[0]))
		offset := uintptr(16) // 8 + 8
		entrySize := unsafe.Sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX{})

		for i := uintptr(0); i < numberOfHandles; i++ {
			entryPtr := unsafe.Pointer(uintptr(unsafe.Pointer(&buf[0])) + offset + (i * entrySize))
			entry := *(*SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)(entryPtr)
			handles = append(handles, entry)
		}

		return handles, nil
	}
}

func getProcessObjectTypeIndex() (uint16, error) {
	myPid, _, _ := procGetCurrentProcessId.Call()
	hProcess, _, _ := procOpenProcess.Call(uintptr(PROCESS_QUERY_LIMITED_INFORMATION), 0, myPid)
	if hProcess == 0 {
		return 0, fmt.Errorf("failed to open current process")
	}
	defer procCloseHandle.Call(hProcess)

	handles, err := getSystemHandles()
	if err != nil {
		return 0, err
	}

	for _, h := range handles {
		if h.UniqueProcessId == myPid && h.HandleValue == hProcess {
			return h.ObjectTypeIndex, nil
		}
	}
	return 0, fmt.Errorf("process handle not found")
}

func getHandleTargetPid(hSourceProcess uintptr, hSourceHandle uintptr) (uint32, error) {
	hCurrentProcess := uintptr(^uintptr(0)) 
	var hTargetHandle uintptr

	ret, _, _ := procDuplicateHandle.Call(
		hSourceProcess,
		hSourceHandle,
		hCurrentProcess,
		uintptr(unsafe.Pointer(&hTargetHandle)),
		0,
		0,
		uintptr(DUPLICATE_SAME_ACCESS),
	)

	if ret == 0 {
		return 0, fmt.Errorf("DuplicateHandle failed")
	}
	defer procCloseHandle.Call(hTargetHandle)

	pid, _, _ := procGetProcessId.Call(hTargetHandle)
	if pid == 0 {
		return 0, fmt.Errorf("invalid pid")
	}
	return uint32(pid), nil
}

func runExposedScan(target string) {
	// If checking specific PID
	if target != "all" {
		targetPid, _ := strconv.Atoi(target)
		fmt.Printf("[*] Checking for processes holding handles TO PID: %d...\n", targetPid)
		
		targetIL, err := getProcessIntegrityLevel(uint32(targetPid))
		if err == nil {
			fmt.Printf("[*] Target Integrity Level: %s (RID: %d)\n", targetIL.Name, targetIL.RID)
		} else {
			fmt.Printf("[!] Warning: Could not get Target Integrity Level: %v\n", err)
		}
	} else {
		fmt.Printf("[*] Checking for ALL processes holding high-privilege handles TO high-integrity processes...\n")
	}

	// 1. Identify Process Object Type Index
	processTypeIndex, err := getProcessObjectTypeIndex()
	if err != nil {
		fmt.Printf("[-] Failed to identify Process Object Type: %v\n", err)
		return
	}
	
	// 2. Get All System Handles
	fmt.Println("[*] Enumerating system handles...")
	handles, err := getSystemHandles()
	if err != nil {
		fmt.Printf("[-] Failed to enumerate handles: %v\n", err)
		return
	}
	
	found := 0
	
	for _, h := range handles {
		// Filter: Must be Process Type
		if h.ObjectTypeIndex != processTypeIndex {
			continue
		}

		ownerPid := uint32(h.UniqueProcessId)
		
		// To check what this handle points to, we need to duplicate it.
		// We need PROCESS_DUP_HANDLE access to the Owner.
		hOwner, _, _ := procOpenProcess.Call(uintptr(PROCESS_DUP_HANDLE), 0, uintptr(ownerPid))
		if hOwner == 0 {
			continue // Can't duplicate from this process
		}

		actualTargetPid, err := getHandleTargetPid(hOwner, h.HandleValue)
		procCloseHandle.Call(hOwner) 
		
		if err != nil {
			continue
		}

		// FILTER LOGIC
		// If target is specific PID: check if actualTargetPid == targetPid
		// If target is "all": check if this is a LEAK (Low -> High)
		
		isMatch := false
		if target != "all" {
			targetPidInt, _ := strconv.Atoi(target)
			if actualTargetPid == uint32(targetPidInt) {
				isMatch = true
			}
		} else {
			// For "all", we only care if it looks like a leak.
			// Optimization: We check ILs below anyway.
			isMatch = true
		}

		if !isMatch {
			continue
		}
		
		// Skip self-reference
		if ownerPid == actualTargetPid {
			continue
		}

		// Get Details
		ownerIL, err := getProcessIntegrityLevel(ownerPid)
		if err != nil { continue }
		
		targetIL, err := getProcessIntegrityLevel(actualTargetPid)
		if err != nil { continue }

		ownerName := "<unknown>"
		// Try to get owner name
		hOwnerQuery, _, _ := procOpenProcess.Call(uintptr(PROCESS_QUERY_LIMITED_INFORMATION), 0, uintptr(ownerPid))
		if hOwnerQuery != 0 {
			pathBuf := make([]uint16, MAX_PATH)
			size := uint32(MAX_PATH)
			r, _, _ := procQueryFullProcessImageNameW.Call(hOwnerQuery, 0, uintptr(unsafe.Pointer(&pathBuf[0])), uintptr(unsafe.Pointer(&size)))
			if r != 0 {
				path := syscall.UTF16ToString(pathBuf[:size])
				parts := strings.Split(path, "\\")
				if len(parts) > 0 {
					ownerName = parts[len(parts)-1]
				}
			}
			procCloseHandle.Call(hOwnerQuery)
		}

		// Determine if it's a leak (Low -> High)
		isLeak := false
		if targetIL.RID > 0 && ownerIL.RID < targetIL.RID {
			isLeak = true
		}
		
		// If scanning ALL, only show LEAKS
		if target == "all" && !isLeak {
			continue
		}

		// Determine access level
		accessStr := decodeAccessMask(h.GrantedAccess)

		prefix := "[*]"
		if isLeak {
			prefix = "[!] LEAK DETECTED:"
		}

		fmt.Printf("%s Owner: PID %d (%s) | IL: %s -> Target PID %d (%s)\n", prefix, ownerPid, ownerName, ownerIL.Name, actualTargetPid, targetIL.Name)
		fmt.Printf("    Handle: 0x%X | Access: %s\n", h.HandleValue, accessStr)
		found++
	}
	
	fmt.Printf("[*] Scan complete. Found %d interesting handles.\n", found)
}

func decodeAccessMask(mask uint32) string {
	if (mask & PROCESS_ALL_ACCESS) == PROCESS_ALL_ACCESS {
		return fmt.Sprintf("0x%X (PROCESS_ALL_ACCESS)", mask)
	}

	var rights []string
	
	// Specific Process Rights
	if (mask & PROCESS_TERMINATE) != 0 { rights = append(rights, "TERMINATE") }
	if (mask & PROCESS_CREATE_THREAD) != 0 { rights = append(rights, "CREATE_THREAD") }
	if (mask & PROCESS_VM_OPERATION) != 0 { rights = append(rights, "VM_OPERATION") }
	if (mask & PROCESS_VM_READ) != 0 { rights = append(rights, "VM_READ") }
	if (mask & PROCESS_VM_WRITE) != 0 { rights = append(rights, "VM_WRITE") }
	if (mask & PROCESS_DUP_HANDLE) != 0 { rights = append(rights, "DUP_HANDLE") }
	if (mask & PROCESS_CREATE_PROCESS) != 0 { rights = append(rights, "CREATE_PROCESS") }
	if (mask & PROCESS_SET_QUOTA) != 0 { rights = append(rights, "SET_QUOTA") }
	if (mask & PROCESS_SET_INFORMATION) != 0 { rights = append(rights, "SET_INFO") }
	if (mask & PROCESS_QUERY_INFORMATION) != 0 { rights = append(rights, "QUERY_INFO") }
	if (mask & PROCESS_SUSPEND_RESUME) != 0 { rights = append(rights, "SUSPEND_RESUME") }
	if (mask & PROCESS_QUERY_LIMITED_INFORMATION) != 0 { rights = append(rights, "QUERY_LIMITED_INFO") }

	// Generic Rights
	if (mask & DELETE) != 0 { rights = append(rights, "DELETE") }
	if (mask & READ_CONTROL) != 0 { rights = append(rights, "READ_CONTROL") }
	if (mask & WRITE_DAC) != 0 { rights = append(rights, "WRITE_DAC") }
	if (mask & WRITE_OWNER) != 0 { rights = append(rights, "WRITE_OWNER") }
	if (mask & SYNCHRONIZE) != 0 { rights = append(rights, "SYNCHRONIZE") }

	if len(rights) == 0 {
		return fmt.Sprintf("0x%X", mask)
	}
	return fmt.Sprintf("0x%X (%s)", mask, strings.Join(rights, ", "))
}


// --- Token Scan Functionality ---

func runTokenScan(target string) {
	fmt.Printf("[*] Starting Token Privilege Scan (Target: %s)...\n", target)

	if target != "all" {
		pid, _ := strconv.Atoi(target)
		// For single PID, we need to create a dummy PE32 to pass, or fetch name
		// For simplicity, we'll fetch name if possible or just pass empty PE32 with correct PID logic
		// But scanPidToken relies on PE32 from loop.
		// Let's refactor slightly to just get name inside scanPidToken if needed,
		// OR pass name to it.
		// Actually, let's fix the call signature to pass name.
		name := "<unknown>"
		
		// Get name for single PID
		hSnap, _, _ := procCreateToolhelp32Snapshot.Call(uintptr(TH32CS_SNAPPROCESS), 0)
		if int32(hSnap) != -1 {
			var pe32 PROCESSENTRY32
			pe32.Size = uint32(unsafe.Sizeof(pe32))
			ret, _, _ := procProcess32First.Call(hSnap, uintptr(unsafe.Pointer(&pe32)))
			for ret != 0 {
				if pe32.ProcessID == uint32(pid) {
					name = syscall.UTF16ToString(pe32.ExeFile[:])
					break
				}
				ret, _, _ = procProcess32Next.Call(hSnap, uintptr(unsafe.Pointer(&pe32)))
			}
			procCloseHandle.Call(hSnap)
		}
		
		scanPidToken(uint32(pid), name)
		return
	}

	// Scan all
	hSnap, _, _ := procCreateToolhelp32Snapshot.Call(uintptr(TH32CS_SNAPPROCESS), 0)
	if int32(hSnap) == -1 {
		fmt.Println("[-] Failed to create snapshot")
		return
	}
	defer procCloseHandle.Call(hSnap)

	var pe32 PROCESSENTRY32
	pe32.Size = uint32(unsafe.Sizeof(pe32))

	ret, _, _ := procProcess32First.Call(hSnap, uintptr(unsafe.Pointer(&pe32)))
	for ret != 0 {
		pid := pe32.ProcessID
		if pid != 0 {
			name := syscall.UTF16ToString(pe32.ExeFile[:])
			scanPidToken(pid, name)
		}
		ret, _, _ = procProcess32Next.Call(hSnap, uintptr(unsafe.Pointer(&pe32)))
	}
}

func scanPidToken(pid uint32, procName string) {
	// We need TOKEN_QUERY
	hProcess, _, _ := procOpenProcess.Call(uintptr(PROCESS_QUERY_LIMITED_INFORMATION), 0, uintptr(pid))
	if hProcess == 0 {
		return
	}
	defer procCloseHandle.Call(hProcess)

	var hToken uintptr
	ret, _, _ := procOpenProcessToken.Call(hProcess, uintptr(TOKEN_QUERY), uintptr(unsafe.Pointer(&hToken)))
	if ret == 0 {
		return
	}
	defer procCloseHandle.Call(hToken)

	privs, err := getTokenPrivileges(hToken)
	if err != nil {
		return
	}

	dangerous := []string{
		"SeDebugPrivilege",
		"SeImpersonatePrivilege",
		"SeAssignPrimaryTokenPrivilege",
		"SeTcbPrivilege",
		"SeBackupPrivilege",
		"SeRestorePrivilege",
		"SeLoadDriverPrivilege",
	}

	foundDangerous := false
	var foundList []string

	for _, p := range privs {
		for _, d := range dangerous {
			if strings.EqualFold(p, d) {
				foundDangerous = true
				foundList = append(foundList, p)
			}
		}
	}

	if foundDangerous {
		fmt.Printf("[!] PID %d (%s) has dangerous privileges: %v\n", pid, procName, foundList)
	}
}

func getTokenPrivileges(hToken uintptr) ([]string, error) {
	var returnLength uint32
	procGetTokenInformation.Call(hToken, uintptr(TokenPrivileges), 0, 0, uintptr(unsafe.Pointer(&returnLength)))
	if returnLength == 0 {
		return nil, fmt.Errorf("failed size")
	}

	buf := make([]byte, returnLength)
	ret, _, _ := procGetTokenInformation.Call(hToken, uintptr(TokenPrivileges), uintptr(unsafe.Pointer(&buf[0])), uintptr(returnLength), uintptr(unsafe.Pointer(&returnLength)))
	if ret == 0 {
		return nil, fmt.Errorf("failed get")
	}

	count := *(*uint32)(unsafe.Pointer(&buf[0]))
	var privileges []string
	
	// Offset logic:
	// Count (4) + Privileges Array
	// LUID_AND_ATTRIBUTES is 12 bytes (8 LUID + 4 Attr)
	// LUID is 4 byte aligned.
	
	startOffset := uintptr(4)
	itemSize := unsafe.Sizeof(LUID_AND_ATTRIBUTES{}) // 12 bytes

	for i := uint32(0); i < count; i++ {
		itemPtr := unsafe.Pointer(uintptr(unsafe.Pointer(&buf[0])) + startOffset + (uintptr(i) * itemSize))
		item := *(*LUID_AND_ATTRIBUTES)(itemPtr)

		// Check attribute SE_PRIVILEGE_ENABLED = 0x00000002
		if (item.Attributes & 0x00000002) != 0 {
			name, err := lookupPrivilegeName(item.Luid)
			if err == nil {
				privileges = append(privileges, name)
			}
		}
	}

	return privileges, nil
}

func lookupPrivilegeName(luid LUID) (string, error) {
	bufLen := uint32(256)
	buf := make([]uint16, bufLen)

	ret, _, err := procLookupPrivilegeNameW.Call(
		0, 
		uintptr(unsafe.Pointer(&luid)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&bufLen)),
	)
	if ret == 0 {
		return "", err
	}
	return syscall.UTF16ToString(buf), nil
}

// --- Common Helpers ---

func getProcessIntegrityLevel(pid uint32) (IntegrityInfo, error) {
	hProcess, _, _ := procOpenProcess.Call(uintptr(PROCESS_QUERY_LIMITED_INFORMATION), 0, uintptr(pid))
	if hProcess == 0 {
		return IntegrityInfo{}, fmt.Errorf("Access Denied")
	}
	defer procCloseHandle.Call(hProcess)

	var hToken uintptr
	ret, _, _ := procOpenProcessToken.Call(hProcess, uintptr(TOKEN_QUERY), uintptr(unsafe.Pointer(&hToken)))
	if ret == 0 {
		return IntegrityInfo{}, fmt.Errorf("OpenProcessToken failed")
	}
	defer procCloseHandle.Call(hToken)

	var returnLength uint32
	procGetTokenInformation.Call(hToken, uintptr(TokenIntegrityLevel), 0, 0, uintptr(unsafe.Pointer(&returnLength)))
	if returnLength == 0 {
		return IntegrityInfo{}, fmt.Errorf("GetTokenInformation size failed")
	}

	buf := make([]byte, returnLength)
	ret, _, _ = procGetTokenInformation.Call(hToken, uintptr(TokenIntegrityLevel), uintptr(unsafe.Pointer(&buf[0])), uintptr(returnLength), uintptr(unsafe.Pointer(&returnLength)))
	if ret == 0 {
		return IntegrityInfo{}, fmt.Errorf("GetTokenInformation data failed")
	}

	tml := (*TOKEN_MANDATORY_LABEL)(unsafe.Pointer(&buf[0]))
	name, rid := getIntegrityLevelFromSID(tml.Label.Sid)
	return IntegrityInfo{Name: name, RID: rid}, nil
}

func getIntegrityLevelFromSID(sidPtr uintptr) (string, uint32) {
	count := *(*byte)(unsafe.Pointer(sidPtr + 1))
	if count == 0 {
		return "Unknown", 0
	}
	lastSubAuthOffset := 8 + uintptr(count-1)*4
	rid := *(*uint32)(unsafe.Pointer(sidPtr + lastSubAuthOffset))

	switch {
	case rid < SECURITY_MANDATORY_LOW_RID:
		return "Untrusted", rid
	case rid >= SECURITY_MANDATORY_LOW_RID && rid < SECURITY_MANDATORY_MEDIUM_RID:
		return "Low", rid
	case rid >= SECURITY_MANDATORY_MEDIUM_RID && rid < SECURITY_MANDATORY_HIGH_RID:
		return "Medium", rid
	case rid >= SECURITY_MANDATORY_HIGH_RID && rid < SECURITY_MANDATORY_SYSTEM_RID:
		return "High", rid
	case rid >= SECURITY_MANDATORY_SYSTEM_RID:
		return "System", rid
	default:
		return "Unknown", rid
	}
}
