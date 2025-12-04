# 04 - Detection Rules Guide

This guide covers creating detection rules and alerts in your SIEM to identify security threats.

---

## Detection Philosophy

### MITRE ATT&CK Framework

We align our detections with [MITRE ATT&CK](https://attack.mitre.org/), which categorizes adversary tactics and techniques:

| Tactic | Description | Priority |
|--------|-------------|----------|
| Initial Access | How attackers get in | High |
| Execution | Running malicious code | Critical |
| Persistence | Maintaining access | High |
| Privilege Escalation | Gaining higher privileges | Critical |
| Defense Evasion | Avoiding detection | High |
| Credential Access | Stealing credentials | Critical |
| Discovery | Learning about environment | Medium |
| Lateral Movement | Moving through network | High |
| Collection | Gathering data | Medium |
| Exfiltration | Stealing data | Critical |

---

## Part 1: Splunk Detection Rules

### Authentication Attacks

#### Brute Force Detection (T1110)
```spl
index=windows sourcetype="WinEventLog:Security" EventCode=4625
| bin _time span=5m
| stats count by src_ip, user, _time
| where count > 10
| eval alert_severity="high"
| eval attack_technique="T1110 - Brute Force"
```

#### Successful Login After Multiple Failures
```spl
index=windows sourcetype="WinEventLog:Security" (EventCode=4625 OR EventCode=4624)
| transaction user maxspan=10m
| where eventcount > 5 AND match(EventCode, "4624")
| eval alert_severity="critical"
| eval attack_technique="T1110 - Brute Force (Successful)"
```

#### Login from Unusual Location
```spl
index=windows sourcetype="WinEventLog:Security" EventCode=4624 Logon_Type=10
| iplocation src_ip
| search NOT (Country="United States" OR Country="Canada")
| eval alert_severity="medium"
| eval attack_technique="T1078 - Valid Accounts"
```

### Credential Dumping

#### LSASS Access Detection (T1003.001)
```spl
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
| where NOT match(SourceImage, "(?i)(MsMpEng|csrss|wininit|services)")
| eval alert_severity="critical"
| eval attack_technique="T1003.001 - LSASS Memory"
| table _time, Computer, SourceImage, SourceUser, GrantedAccess
```

#### Mimikatz Execution Detection
```spl
index=sysmon EventCode=1
| regex CommandLine="(?i)(sekurlsa|kerberos::list|crypto::capi|privilege::debug|lsadump)"
| eval alert_severity="critical"
| eval attack_technique="T1003 - Credential Dumping"
| table _time, Computer, User, CommandLine, ParentCommandLine
```

#### SAM Database Access
```spl
index=sysmon EventCode=1
| regex CommandLine="(?i)(reg.*save.*sam|reg.*save.*system|vssadmin.*shadows)"
| eval alert_severity="critical"
| eval attack_technique="T1003.002 - SAM"
```

### Suspicious PowerShell

#### Encoded PowerShell Commands (T1059.001)
```spl
index=sysmon EventCode=1 Image="*\\powershell.exe"
| regex CommandLine="(?i)(-enc|-encodedcommand|-e\s+[A-Za-z0-9+/=]{20,})"
| eval alert_severity="high"
| eval attack_technique="T1059.001 - PowerShell"
| table _time, Computer, User, CommandLine
```

#### PowerShell Download Cradle
```spl
index=sysmon EventCode=1 Image="*\\powershell.exe"
| regex CommandLine="(?i)(Invoke-WebRequest|wget|curl|DownloadString|DownloadFile|Net\.WebClient)"
| eval alert_severity="high"
| eval attack_technique="T1105 - Ingress Tool Transfer"
```

#### PowerShell Execution Policy Bypass
```spl
index=sysmon EventCode=1 Image="*\\powershell.exe"
| regex CommandLine="(?i)(-ep bypass|-executionpolicy bypass|Set-ExecutionPolicy)"
| eval alert_severity="medium"
| eval attack_technique="T1059.001 - PowerShell"
```

### Persistence Mechanisms

#### Registry Run Key Modification (T1547.001)
```spl
index=sysmon EventCode=13
| regex TargetObject="(?i)(CurrentVersion\\\\Run|CurrentVersion\\\\RunOnce)"
| eval alert_severity="high"
| eval attack_technique="T1547.001 - Registry Run Keys"
| table _time, Computer, User, TargetObject, Details
```

#### Scheduled Task Creation (T1053.005)
```spl
index=sysmon EventCode=1
| regex CommandLine="(?i)(schtasks.*\/create|Register-ScheduledTask)"
| eval alert_severity="medium"
| eval attack_technique="T1053.005 - Scheduled Task"
| table _time, Computer, User, CommandLine
```

#### New Service Creation
```spl
index=windows sourcetype="WinEventLog:System" EventCode=7045
| eval alert_severity="medium"
| eval attack_technique="T1543.003 - Windows Service"
| table _time, Computer, ServiceName, ImagePath, ServiceType
```

### Lateral Movement

#### PsExec Usage (T1570)
```spl
index=sysmon EventCode=1
| regex CommandLine="(?i)(psexec|paexec|remcom)"
| eval alert_severity="high"
| eval attack_technique="T1570 - Lateral Tool Transfer"
| table _time, Computer, User, CommandLine, ParentImage
```

#### Remote WMI Execution
```spl
index=sysmon EventCode=1 Image="*\\wmic.exe"
| regex CommandLine="(?i)(\/node:|process call create)"
| eval alert_severity="high"
| eval attack_technique="T1047 - WMI"
```

#### RDP Connections
```spl
index=windows sourcetype="WinEventLog:Security" EventCode=4624 Logon_Type=10
| stats count by src_ip, user, dest
| where count > 3
| eval alert_severity="medium"
| eval attack_technique="T1021.001 - Remote Desktop Protocol"
```

---

## Part 2: Elastic/KQL Detection Rules

### Authentication Attacks

#### Brute Force Detection
```kql
event.code: "4625" 
| stats count by source.ip, user.name
| where count > 10
```

#### Successful Login After Failures
```kql
event.code: ("4625" or "4624") and user.name: *
| sort @timestamp
| transaction user.name maxspan=10m
```

### Credential Access

#### LSASS Access
```kql
event.code: "10" and winlog.event_data.TargetImage: *lsass.exe
and not winlog.event_data.SourceImage: (*MsMpEng* or *csrss* or *wininit*)
```

### Suspicious Execution

#### Encoded PowerShell
```kql
process.name: "powershell.exe" 
and process.command_line: (*-enc* or *-encodedcommand* or *-e *)
```

---

## Part 3: Sigma Rules

Sigma rules are vendor-agnostic detection rules that can be converted to Splunk, Elastic, and other formats.

### Example: Mimikatz Detection
See `detection-rules/sigma-rules/windows-credential-access.yml`

### Converting Sigma Rules

```bash
# Install sigmac
pip install sigma-cli

# Convert to Splunk
sigma convert -t splunk rules/windows/credential-access.yml

# Convert to Elasticsearch
sigma convert -t elasticsearch rules/windows/credential-access.yml
```

---

## Part 4: Alert Configuration

### Splunk Alerts

1. Run your search
2. Click **Save As → Alert**
3. Configure:
   - Alert Type: Real-time or Scheduled
   - Trigger Conditions: Number of results > 0
   - Actions: Email, Slack, TheHive, etc.

Example alert for critical events:
```spl
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
| where NOT match(SourceImage, "(?i)(MsMpEng|csrss|wininit)")
| eval severity="CRITICAL"
| table _time, Computer, SourceImage, SourceUser
```

### Elastic Detection Rules

In Kibana:
1. Go to **Security → Rules → Create new rule**
2. Select rule type (Custom query, Threshold, etc.)
3. Configure query and severity
4. Set actions

---

## Part 5: Detection Tuning

### Reducing False Positives

1. **Whitelist legitimate processes**
```spl
| where NOT match(SourceImage, "(?i)(legitimate_app1|legitimate_app2)")
```

2. **Baseline normal behavior**
```spl
index=sysmon EventCode=1
| stats count by Image
| sort - count
| head 100
```

3. **Add context**
```spl
| lookup user_department user OUTPUT department
| where department != "IT"
```

### Testing Detections

Use Atomic Red Team to validate:
```powershell
# Install Atomic Red Team
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)

# Run specific test
Invoke-AtomicTest T1003.001 -TestNumbers 1
```

---

## Detection Use Case Checklist

| ID | Use Case | MITRE ID | Splunk | Elastic | Status |
|----|----------|----------|--------|---------|--------|
| UC-001 | Brute Force | T1110 | ✅ | ✅ | Active |
| UC-002 | LSASS Access | T1003.001 | ✅ | ✅ | Active |
| UC-003 | Encoded PowerShell | T1059.001 | ✅ | ✅ | Active |
| UC-004 | Registry Persistence | T1547.001 | ✅ | ✅ | Active |
| UC-005 | Scheduled Tasks | T1053.005 | ✅ | ✅ | Active |
| UC-006 | Mimikatz | T1003 | ✅ | ✅ | Active |
| UC-007 | PsExec | T1570 | ✅ | 🔄 | Testing |
| UC-008 | Data Exfil | T1041 | 📋 | 📋 | Planned |

---

## Next Steps

Once your detections are configured, proceed to:
- [05 - Attack Simulation](05-Attack-Simulation.md)
