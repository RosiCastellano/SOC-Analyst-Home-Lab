# 03 - Log Collection Guide

This guide covers configuring log collection from various sources to your SIEM.

---

## Log Collection Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         LOG SOURCES                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           │
│  │  Windows 10  │  │   Windows    │  │    Linux     │           │
│  │  Workstation │  │   Server     │  │   Servers    │           │
│  │              │  │              │  │              │           │
│  │  • Sysmon    │  │  • Sysmon    │  │  • Auditd    │           │
│  │  • WinEvt    │  │  • WinEvt    │  │  • Syslog    │           │
│  │  • PowerShell│  │  • AD Logs   │  │  • Auth logs │           │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘           │
│         │                 │                  │                  │
│         ▼                 ▼                  ▼                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           │
│  │   Splunk UF  │  │   Splunk UF  │  │  Filebeat    │           │
│  │      or      │  │      or      │  │      or      │           │
│  │  Winlogbeat  │  │  Winlogbeat  │  │ Splunk UF    │           │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘           │
│         │                 │                  │                  │
│         └─────────────────┼──────────────────┘                  │
│                           │                                     │
│                           ▼                                     │
│                  ┌──────────────────┐                           │
│                  │   SIEM Server    │                           │
│                  │  (Splunk/ELK)    │                           │
│                  │   10.0.0.10      │                           │
│                  └──────────────────┘                           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Part 1: Windows Log Collection

### 1.1 Install Sysmon

Sysmon provides detailed Windows event logging essential for security monitoring.

#### Download Sysmon
```powershell
# Download Sysmon
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "C:\Sysmon.zip"
Expand-Archive -Path "C:\Sysmon.zip" -DestinationPath "C:\Sysmon"
```

#### Install with Configuration
```powershell
# Download SwiftOnSecurity config (or use provided config)
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "C:\Sysmon\sysmonconfig.xml"

# Install Sysmon
C:\Sysmon\Sysmon64.exe -accepteula -i C:\Sysmon\sysmonconfig.xml
```

#### Verify Installation
```powershell
# Check service
Get-Service Sysmon64

# View Sysmon logs
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10
```

### 1.2 Configure Windows Event Logging

Enable advanced audit policies:

```powershell
# Enable PowerShell Script Block Logging
New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1

# Enable PowerShell Module Logging
New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1

# Enable Command Line Logging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1
```

### 1.3 Splunk Universal Forwarder (Windows)

#### Download and Install
```powershell
# Download from Splunk.com or use this command
# Install silently
msiexec.exe /i splunkforwarder-9.1.0-x64-release.msi RECEIVING_INDEXER="10.0.0.10:9997" AGREETOLICENSE=yes SPLUNKPASSWORD=changeme /quiet
```

#### Configure inputs.conf
Create `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`:

```ini
[default]
host = WIN10-PC

# Windows Security Events
[WinEventLog://Security]
disabled = 0
index = windows
sourcetype = WinEventLog:Security

# Windows System Events
[WinEventLog://System]
disabled = 0
index = windows
sourcetype = WinEventLog:System

# Windows Application Events
[WinEventLog://Application]
disabled = 0
index = windows
sourcetype = WinEventLog:Application

# Sysmon Events
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = sysmon
sourcetype = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
renderXml = true

# PowerShell Events
[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = 0
index = windows
sourcetype = WinEventLog:PowerShell

[WinEventLog://Windows PowerShell]
disabled = 0
index = windows
sourcetype = WinEventLog:PowerShell
```

#### Configure outputs.conf
Create `C:\Program Files\SplunkUniversalForwarder\etc\system\local\outputs.conf`:

```ini
[tcpout]
defaultGroup = splunk-indexers

[tcpout:splunk-indexers]
server = 10.0.0.10:9997

[tcpout-server://10.0.0.10:9997]
```

#### Restart Forwarder
```powershell
Restart-Service SplunkForwarder
```

### 1.4 Winlogbeat (Alternative for ELK)

#### Download and Install
```powershell
# Download Winlogbeat
Invoke-WebRequest -Uri "https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-8.11.0-windows-x86_64.zip" -OutFile "winlogbeat.zip"
Expand-Archive -Path "winlogbeat.zip" -DestinationPath "C:\Program Files"
Rename-Item "C:\Program Files\winlogbeat-8.11.0-windows-x86_64" "C:\Program Files\Winlogbeat"
```

#### Configure winlogbeat.yml
See `configs/winlogbeat.yml` for full configuration.

Key settings:
```yaml
winlogbeat.event_logs:
  - name: Security
  - name: Microsoft-Windows-Sysmon/Operational
  - name: Microsoft-Windows-PowerShell/Operational
  - name: System
  - name: Application

output.elasticsearch:
  hosts: ["10.0.0.10:9200"]
  username: "elastic"
  password: "YOUR_PASSWORD"
```

#### Install as Service
```powershell
cd "C:\Program Files\Winlogbeat"
.\install-service-winlogbeat.ps1
Start-Service winlogbeat
```

---

## Part 2: Linux Log Collection

### 2.1 Configure Auditd

```bash
# Install auditd
sudo apt install -y auditd audispd-plugins

# Add audit rules
sudo nano /etc/audit/rules.d/audit.rules
```

Add rules:
```
# Log all commands
-a always,exit -F arch=b64 -S execve -k command_execution
-a always,exit -F arch=b32 -S execve -k command_execution

# Monitor /etc/passwd changes
-w /etc/passwd -p wa -k passwd_changes

# Monitor /etc/shadow changes
-w /etc/shadow -p wa -k shadow_changes

# Monitor sudoers
-w /etc/sudoers -p wa -k sudoers_changes

# Monitor SSH
-w /var/log/auth.log -p wa -k auth_log

# Monitor cron
-w /etc/crontab -p wa -k cron_changes
-w /etc/cron.d/ -p wa -k cron_changes
```

```bash
# Restart auditd
sudo systemctl restart auditd
```

### 2.2 Splunk Universal Forwarder (Linux)

```bash
# Download and install
wget -O splunkforwarder.deb "https://download.splunk.com/products/universalforwarder/releases/9.1.0/linux/splunkforwarder-9.1.0-linux-2.6-amd64.deb"
sudo dpkg -i splunkforwarder.deb

# Start and accept license
sudo /opt/splunkforwarder/bin/splunk start --accept-license

# Enable boot start
sudo /opt/splunkforwarder/bin/splunk enable boot-start
```

#### Configure inputs.conf
Create `/opt/splunkforwarder/etc/system/local/inputs.conf`:

```ini
[default]
host = ubuntu-server

[monitor:///var/log/auth.log]
disabled = 0
index = linux
sourcetype = linux:auth

[monitor:///var/log/syslog]
disabled = 0
index = linux
sourcetype = syslog

[monitor:///var/log/audit/audit.log]
disabled = 0
index = linux
sourcetype = linux:audit

[monitor:///var/log/apache2/access.log]
disabled = 0
index = linux
sourcetype = access_combined

[monitor:///var/log/apache2/error.log]
disabled = 0
index = linux
sourcetype = apache:error
```

### 2.3 Filebeat (For ELK)

```bash
# Install Filebeat
sudo apt install -y filebeat

# Enable modules
sudo filebeat modules enable system
sudo filebeat modules enable auditd

# Configure output
sudo nano /etc/filebeat/filebeat.yml
```

See `configs/filebeat.yml` for full configuration.

```bash
# Start Filebeat
sudo systemctl enable filebeat
sudo systemctl start filebeat
```

---

## Part 3: Network Log Collection

### 3.1 pfSense Syslog to Splunk

On pfSense:
1. Go to **Status → System Logs → Settings**
2. Enable Remote Logging
3. Remote log servers: `10.0.0.10:5514`
4. Select log types to forward

On Splunk, create UDP input:
```ini
[udp://5514]
disabled = 0
index = firewall
sourcetype = pfsense
```

### 3.2 Zeek (Network Traffic Analysis)

```bash
# Install Zeek
sudo apt install -y zeek

# Configure interface
sudo nano /opt/zeek/etc/node.cfg
```

```ini
[zeek]
type=standalone
host=localhost
interface=eth0
```

```bash
# Deploy Zeek
sudo zeekctl deploy

# Forward logs to SIEM
# Add to inputs.conf:
```

```ini
[monitor:///opt/zeek/logs/current]
disabled = 0
index = network
sourcetype = bro:json
```

---

## Part 4: Verification

### Check Splunk Data
```spl
# Search for Windows events
index=windows sourcetype="WinEventLog:Security" | head 10

# Search for Sysmon events
index=sysmon | head 10

# Search for Linux events
index=linux | head 10
```

### Check Elasticsearch Data
```bash
# Query indices
curl -X GET "localhost:9200/_cat/indices?v" -u elastic

# Count documents
curl -X GET "localhost:9200/winlogbeat-*/_count" -u elastic
```

---

## Troubleshooting

### No Data in Splunk
1. Check forwarder status: `splunk list forward-server`
2. Verify connectivity: `telnet 10.0.0.10 9997`
3. Check inputs.conf syntax
4. Review splunkd.log

### No Data in Elasticsearch
1. Check Filebeat: `filebeat test output`
2. Verify Logstash: `tail -f /var/log/logstash/logstash-plain.log`
3. Check index patterns in Kibana

---

## Next Steps

Once log collection is working, proceed to:
- [04 - Detection Rules](04-Detection-Rules.md)
