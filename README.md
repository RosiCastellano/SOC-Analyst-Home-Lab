# 🛡️ SOC Analyst Home Lab

A comprehensive Security Operations Center (SOC) home lab environment for developing and practicing threat detection, log analysis, and incident response skills.

![Lab Status](https://img.shields.io/badge/Lab%20Status-Active-brightgreen)
![SIEM](https://img.shields.io/badge/SIEM-Splunk%20%7C%20ELK-blue)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## 🎯 Project Objectives

- Build a functional SOC environment for hands-on security training
- Develop proficiency with industry-standard SIEM platforms (Splunk/Elastic)
- Create and tune detection rules aligned with MITRE ATT&CK framework
- Practice incident response workflows with realistic attack simulations
- Document findings and build a professional security portfolio

---

## 🏗️ Lab Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              MANAGEMENT NETWORK                             │
│                                 10.0.0.0/24                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐   │
│  │   Splunk    │    │   Security  │    │   pfSense   │    │   Wazuh     │   │
│  │   Server    │    │   Onion     │    │  Firewall   │    │   Manager   │   │
│  │ 10.0.0.10   │    │ 10.0.0.20   │    │ 10.0.0.1    │    │ 10.0.0.30   │   │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘   │
│         ▲                  ▲                  ▲                  ▲          │
│         │                  │                  │                  │          │
│         └──────────────────┴────────┬─────────┴──────────────────┘          │
│                                     │                                       │
├─────────────────────────────────────┼───────────────────────────────────────┤
│                              VICTIM NETWORK                                 │
│                                10.0.1.0/24                                  │
├─────────────────────────────────────┼───────────────────────────────────────┤
│                                     │                                       │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐   │
│  │  Windows 10 │    │  Windows    │    │   Ubuntu    │    │   Web       │   │
│  │ Workstation │    │  Server     │    │   Server    │    │   Server    │   │
│  │ 10.0.1.10   │    │ 10.0.1.20   │    │ 10.0.1.30   │    │ 10.0.1.40   │   │
│  │  [Sysmon]   │    │   [AD/DC]   │    │  [Zeek]     │    │  [DVWA]     │   │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘   │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                              ATTACKER NETWORK                               │
│                                10.0.2.0/24                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐    ┌─────────────┐                                         │
│  │ Kali Linux  │    │  Commando   │                                         │
│  │  Attacker   │    │     VM      │                                         │
│  │ 10.0.2.10   │    │ 10.0.2.20   │                                         │
│  └─────────────┘    └─────────────┘                                         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 💻 Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 4 cores | 8+ cores |
| RAM | 16 GB | 32+ GB |
| Storage | 200 GB SSD | 500+ GB SSD |
| Network | 1 NIC | 2+ NICs |

### Virtualization Platform Options
- VMware Workstation Pro / Player
- VirtualBox (Free)
- Proxmox VE (Free, Type 1)
- Hyper-V (Windows Pro/Enterprise)

---

## 🖥️ Virtual Machines

| VM Name | OS | Purpose | RAM | Storage |
|---------|----|---------|----- |---------|
| Splunk-Server | Ubuntu 22.04 | SIEM & Log Analysis | 8 GB | 100 GB |
| DC01 | Windows Server 2019 | Active Directory | 4 GB | 60 GB |
| WIN10-PC | Windows 10 | Victim Workstation | 4 GB | 50 GB |
| Ubuntu-Server | Ubuntu 22.04 | Linux Target | 2 GB | 40 GB |
| pfSense | FreeBSD | Firewall & Router | 1 GB | 10 GB |
| Kali-Attacker | Kali Linux | Attack Simulation | 4 GB | 50 GB |

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [01 - Lab Setup](docs/01-Lab-Setup.md) | Initial environment configuration |
| [02 - SIEM Installation](docs/02-SIEM-Installation.md) | Splunk & ELK deployment |
| [03 - Log Collection](docs/03-Log-Collection.md) | Forwarders, Sysmon, Beats |
| [04 - Detection Rules](docs/04-Detection-Rules.md) | Custom alerts & queries |
| [05 - Attack Simulation](docs/05-Attack-Simulation.md) | Red team exercises |

---

## 🔧 Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/RosiCastellano/SOC-Analyst-Home-Lab.git
cd SOC-Analyst-Home-Lab
```

### 2. Set Up Virtual Machines
Follow the [Lab Setup Guide](docs/01-Lab-Setup.md) to create your VMs.

### 3. Install SIEM
Choose your platform and follow the [SIEM Installation Guide](docs/02-SIEM-Installation.md).

### 4. Configure Log Collection
Deploy agents using the [Log Collection Guide](docs/03-Log-Collection.md).

### 5. Create Detection Rules
Implement alerts with the [Detection Rules Guide](docs/04-Detection-Rules.md).

### 6. Test Your Detections
Run attack simulations using the [Attack Simulation Guide](docs/05-Attack-Simulation.md).

---

## 🛠️ Tools & Technologies

### SIEM & Log Management
- Splunk Enterprise (Free License - 500MB/day)
- Elastic Stack (Elasticsearch, Logstash, Kibana)
- Wazuh (XDR & SIEM)

### Log Collection & Forwarding
- Splunk Universal Forwarder
- Winlogbeat / Filebeat
- Sysmon (System Monitor)
- Wazuh Agent

### Network Security Monitoring
- Zeek (Network Analysis)
- Suricata (IDS/IPS)
- Wireshark (Packet Analysis)

### Threat Intelligence
- MISP (Threat Sharing)
- OpenCTI
- Abuse.ch Feeds

### Attack Simulation
- Atomic Red Team
- MITRE Caldera
- Metasploit Framework

---

## 📊 Detection Use Cases

| ID | Use Case | MITRE ATT&CK | Status |
|----|----------|--------------|--------|
| UC-001 | Brute Force Authentication | T1110 | ✅ Implemented |
| UC-002 | Suspicious PowerShell Execution | T1059.001 | ✅ Implemented |
| UC-003 | LSASS Memory Access | T1003.001 | ✅ Implemented |
| UC-004 | Scheduled Task Creation | T1053.005 | ✅ Implemented |
| UC-005 | Registry Run Key Modification | T1547.001 | ✅ Implemented |
| UC-006 | Mimikatz Execution | T1003 | ✅ Implemented |
| UC-007 | Lateral Movement via PsExec | T1570 | 🔄 In Progress |
| UC-008 | Data Exfiltration Detection | T1041 | 📋 Planned |

---

## 📁 Repository Structure

```
SOC-Analyst-Home-Lab/
├── README.md
├── LICENSE
├── docs/
│   ├── 01-Lab-Setup.md
│   ├── 02-SIEM-Installation.md
│   ├── 03-Log-Collection.md
│   ├── 04-Detection-Rules.md
│   └── 05-Attack-Simulation.md
├── configs/
│   ├── sysmon-config.xml
│   ├── winlogbeat.yml
│   ├── filebeat.yml
│   └── suricata.yaml
├── detection-rules/
│   ├── splunk-queries/
│   │   ├── authentication-attacks.spl
│   │   ├── powershell-suspicious.spl
│   │   └── credential-dumping.spl
│   └── sigma-rules/
│       ├── windows-credential-access.yml
│       └── windows-persistence.yml
├── scripts/
│   ├── install-sysmon.ps1
│   ├── deploy-splunk-forwarder.ps1
│   └── setup-elastic-agent.sh
└── screenshots/
    └── .gitkeep
```

---

## 🎓 Skills Developed

- **SIEM Administration** - Splunk & Elastic Stack management
- **Log Analysis** - Windows, Linux, and network log investigation
- **Threat Detection** - Writing and tuning detection rules
- **Incident Response** - Alert triage and investigation workflows
- **Network Security** - Traffic analysis and IDS management
- **MITRE ATT&CK** - Mapping detections to adversary techniques

---

## 📖 Resources

### Training & Learning
- [Splunk Fundamentals 1 (Free)](https://www.splunk.com/en_us/training/free-courses/splunk-fundamentals-1.html)
- [Elastic Training (Free)](https://www.elastic.co/training/free)
- [Blue Team Labs Online](https://blueteamlabs.online/)
- [CyberDefenders](https://cyberdefenders.org/)

### Documentation
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Sigma Rules Repository](https://github.com/SigmaHQ/sigma)
- [Sysmon Configuration Guide](https://github.com/SwiftOnSecurity/sysmon-config)

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**Rosi Castellano**

- GitHub: [@RosiCastellano](https://github.com/RosiCastellano)

---

## ⭐ Acknowledgments

- [SwiftOnSecurity](https://github.com/SwiftOnSecurity) for Sysmon configuration
- [Sigma Rules Project](https://github.com/SigmaHQ/sigma) for detection rules
- The cybersecurity community for knowledge sharing

---
