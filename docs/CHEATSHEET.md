# SOC Analyst Home Lab - Quick Reference Cheat Sheet

## 🔍 Splunk Queries

### Quick Searches
```spl
# All Windows Security Events
index=windows sourcetype="WinEventLog:Security"

# All Sysmon Events
index=sysmon

# Failed Logins (Last 24 Hours)
index=windows EventCode=4625 earliest=-24h

# Successful Logins
index=windows EventCode=4624

# Process Creation (Sysmon)
index=sysmon EventCode=1

# Network Connections (Sysmon)
index=sysmon EventCode=3

# File Creation (Sysmon)
index=sysmon EventCode=11

# Registry Changes (Sysmon)
index=sysmon EventCode=12 OR EventCode=13 OR EventCode=14
```

### Detection Queries
```spl
# Brute Force Detection
index=windows EventCode=4625 | stats count by src_ip, user | where count > 10

# LSASS Access (Credential Dumping)
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"

# Encoded PowerShell
index=sysmon EventCode=1 Image="*\\powershell.exe" | regex CommandLine="(?i)-enc"

# Suspicious Scheduled Tasks
index=sysmon EventCode=1 | regex CommandLine="(?i)schtasks.*/create"

# Registry Run Key Persistence
index=sysmon EventCode=13 | regex TargetObject="(?i)CurrentVersion\\\\Run"
```

---

## 📊 Key Windows Event IDs

### Authentication
| Event ID | Description |
|----------|-------------|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4634 | Logoff |
| 4648 | Logon using explicit credentials |
| 4672 | Special privileges assigned |
| 4720 | User account created |
| 4726 | User account deleted |
| 4740 | Account locked out |

### Sysmon Events
| Event ID | Description |
|----------|-------------|
| 1 | Process creation |
| 3 | Network connection |
| 7 | Image loaded (DLL) |
| 8 | CreateRemoteThread |
| 10 | Process access |
| 11 | File created |
| 12 | Registry key created/deleted |
| 13 | Registry value set |
| 22 | DNS query |

---

## 🎯 MITRE ATT&CK Quick Reference

### Initial Access (TA0001)
- T1566 - Phishing
- T1190 - Exploit Public-Facing App
- T1078 - Valid Accounts

### Execution (TA0002)
- T1059.001 - PowerShell
- T1059.003 - Windows Command Shell
- T1047 - WMI

### Persistence (TA0003)
- T1547.001 - Registry Run Keys
- T1053.005 - Scheduled Task
- T1543.003 - Windows Service

### Credential Access (TA0006)
- T1003.001 - LSASS Memory
- T1003.002 - SAM Database
- T1558.003 - Kerberoasting

### Lateral Movement (TA0008)
- T1021.001 - RDP
- T1021.002 - SMB/Windows Admin Shares
- T1570 - Lateral Tool Transfer

---

## 🛠️ Useful Commands

### Windows
```powershell
# Check Sysmon status
Get-Service Sysmon64

# View Sysmon config
Sysmon64.exe -c

# Check Splunk Forwarder status
Get-Service SplunkForwarder

# List Splunk forwarders
& "C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe" list forward-server

# View recent Sysmon events
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 50
```

### Linux
```bash
# Check Filebeat status
systemctl status filebeat

# Test Filebeat config
filebeat test config
filebeat test output

# View audit logs
ausearch -k command_execution | head -50

# Check connection to Elasticsearch
curl -k -u elastic:password https://10.0.0.10:9200/_cluster/health?pretty
```

### Splunk Server
```bash
# Check Splunk status
/opt/splunk/bin/splunk status

# Check receiving ports
/opt/splunk/bin/splunk display listen

# List connected forwarders
/opt/splunk/bin/splunk list forward-server

# Restart Splunk
/opt/splunk/bin/splunk restart
```

---

## 🔥 Attack Simulation Commands

### Atomic Red Team
```powershell
# Run credential dumping test
Invoke-AtomicTest T1003.001 -TestNumbers 1

# Run persistence test
Invoke-AtomicTest T1547.001 -TestNumbers 1

# Cleanup after test
Invoke-AtomicTest T1003.001 -TestNumbers 1 -Cleanup
```

### Manual Tests
```powershell
# Test encoded PowerShell detection
$cmd = 'Write-Host "Test"'; $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd)); powershell -enc $enc

# Test registry persistence (CLEANUP AFTER!)
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Test" -Value "calc.exe"
# Cleanup:
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Test"
```

---

## 📁 Important File Locations

### Windows
```
Sysmon:           C:\Windows\Sysmon64.exe
Sysmon Config:    C:\Sysmon\sysmonconfig.xml
Splunk Forwarder: C:\Program Files\SplunkUniversalForwarder\
Forwarder Inputs: ...\etc\system\local\inputs.conf
Windows Logs:     C:\Windows\System32\winevt\Logs\
```

### Linux
```
Filebeat Config:  /etc/filebeat/filebeat.yml
Filebeat Logs:    /var/log/filebeat/
Audit Logs:       /var/log/audit/audit.log
Auth Logs:        /var/log/auth.log
Syslog:           /var/log/syslog
```

### Splunk Server
```
Splunk Home:      /opt/splunk/
Indexes:          /opt/splunk/var/lib/splunk/
Apps:             /opt/splunk/etc/apps/
Inputs Config:    /opt/splunk/etc/system/local/inputs.conf
```

---

## 🌐 Network Ports

| Port | Service |
|------|---------|
| 8000 | Splunk Web UI |
| 8089 | Splunk Management |
| 9997 | Splunk Receiving |
| 5601 | Kibana |
| 9200 | Elasticsearch |
| 5044 | Logstash Beats |
| 514 | Syslog (UDP/TCP) |
| 5514 | Syslog Alt (UDP/TCP) |

---

## ⚡ Troubleshooting

### No Data in Splunk
1. Check forwarder: `splunk list forward-server`
2. Test connectivity: `telnet <splunk_ip> 9997`
3. Verify inputs.conf syntax
4. Check splunkd.log for errors

### No Data in Elasticsearch
1. Test Filebeat: `filebeat test output`
2. Check Filebeat logs: `tail -f /var/log/filebeat/filebeat`
3. Verify Elasticsearch is running
4. Check index patterns in Kibana

### Sysmon Not Logging
1. Verify service: `Get-Service Sysmon64`
2. Check config: `Sysmon64.exe -c`
3. Verify Event Log: `Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 1`
