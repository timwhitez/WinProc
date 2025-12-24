# WinProc

**WinProc** is a lightweight Windows process security auditing tool designed to help security researchers, Red Teams, and Blue Teams quickly identify potential privilege escalation vulnerabilities, configuration errors, and sensitive information leaks.

Developed by **TimWhite** (Github: [timwhitez](https://github.com/timwhitez))

---

## 🚀 Features

WinProc supports multiple scan modes to perform a comprehensive security health check on system processes:

*   **🛡️ LPE Opportunities (LPE)**: Scans for high-integrity processes accessible by the current user, checking for dangerous permissions (e.g., `PROCESS_ALL_ACCESS`, `PROCESS_TERMINATE`).
*   **🔓 Handle Leaks**: Detects if low-privileged processes accidentally hold sensitive handles to high-privileged processes (Outbound).
*   **🎯 Handle Exposure**: Detects if other processes hold dangerous handles pointing TO the target process (Inbound).
*   **⚠️ DLL Hijacking**: Scans process modules to identify DLLs loaded from writable directories (e.g., User directory, Temp).
*   **📝 Configuration Vulns**: Detects Unquoted Service Path vulnerabilities.
*   **🔑 Token Privileges**: Checks if processes have enabled dangerous Token privileges (e.g., `SeDebugPrivilege`, `SeImpersonatePrivilege`).
*   **ℹ️ Basic Info**: Quickly retrieves the full image path and command line arguments.

---

## 🛠️ Build

Ensure you have a Go environment installed.

```bash
set GOOS=windows
go build -o winproc.exe
```

---

## 📖 Usage

WinProc uses a unified `-scan` argument to specify the mode, combined with `-pid` to target specific processes.

```text
Usage: winproc.exe [options]

Core Commands:
  -scan <mode>      Select scan mode (Required)
                    Available Modes:
                      info      : Show process image path and command line
                      vulnpath  : Scan for Unquoted Service Paths (Config Issues)
                      dlls      : Scan for DLL Hijacking (writable loaded DLLs)
                      handles   : Scan handles HELD BY process (Outbound / Leaks)
                      exposed   : Scan handles pointing TO process (Inbound / Exposure)
                      token     : Scan for dangerous token privileges
                      lpe       : Scan for PrivEsc opportunities (High integrity procs)
                      all       : Run ALL scans (Recommended for full audit)

Options:
  -pid <id>         Target a specific PID (Default: scans all processes)
```

---

## 💡 Typical Scenarios

### 1. Full System Security Audit (Recommended)
Scans the entire system with current user privileges to find all potential exploitation opportunities.
```cmd
winproc.exe -scan all
```

### 2. Check for Process Termination Rights
Checks if the current user has `PROCESS_TERMINATE` or `PROCESS_ALL_ACCESS` rights on PID 1234.
```cmd
winproc.exe -scan lpe -pid 1234
```

### 3. Investigate Handle Exposure
Checks if any low-privileged processes hold sensitive handles to PID 8888 (which could compromise it).
```cmd
winproc.exe -scan exposed -pid 8888
```

### 4. Quick Process Info
Retrieves the full path and startup arguments for PID 1234.
```cmd
winproc.exe -scan info -pid 1234
```

---

## ⚠️ Disclaimer

This tool is for security research and authorized testing purposes only. Do not use this tool for any unauthorized malicious activities. The developer assumes no liability for any consequences resulting from the use of this tool.

---

## 🔗 About

*   **Author**: TimWhite
*   **Github**: [https://github.com/timwhitez](https://github.com/timwhitez)
