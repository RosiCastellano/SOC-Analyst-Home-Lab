# SOC Analyst Home Lab

A self-contained Security Operations Center (SOC) lab environment for developing
and demonstrating threat detection, log analysis, and incident response skills.
The lab covers SIEM deployment, multi-source log collection, MITRE ATT&CK-aligned
detection engineering, adversary simulation, and documented incident response.

---

## Project Objectives

- Build a functional SOC environment suitable for hands-on detection engineering
  and incident response practice.
- Develop working proficiency with industry-standard SIEM platforms (Splunk and
  the Elastic Stack).
- Author and tune detection rules mapped to the MITRE ATT&CK framework.
- Validate detections against real attack techniques using adversary simulation.
- Document a complete incident response workflow from alert to recovery.

---

## Lab Architecture

```
+-----------------------------------------------------------------------------+
|                            MANAGEMENT NETWORK                               |
|                               10.0.0.0/24                                   |
+-----------------------------------------------------------------------------+
|                                                                             |
|   Splunk Server        Security Onion       pfSense           Wazuh Mgr     |
|   10.0.0.10            10.0.0.20            10.0.0.1           10.0.0.30    |
|                                                                             |
+-----------------------------------------------------------------------------+
|                              VICTIM NETWORK                                 |
|                               10.0.1.0/24                                   |
+-----------------------------------------------------------------------------+
|                                                                             |
|   Windows 10           Windows Server      Ubuntu Server      Web Server    |
|   10.0.1.10 [Sysmon]   10.0.1.20 [AD/DC]   10.0.1.30 [Zeek]   10.0.1.40     |
|                                                                             |
+-----------------------------------------------------------------------------+
|                             ATTACKER NETWORK                                |
|                               10.0.2.0/24                                   |
+-----------------------------------------------------------------------------+
|                                                                             |
|   Kali Linux           Commando VM                                          |
|   10.0.2.10            10.0.2.20                                            |
|                                                                             |
+-----------------------------------------------------------------------------+
```

---

## Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 4 cores | 8 or more cores |
| RAM | 16 GB | 32 GB or more |
| Storage | 200 GB SSD | 500 GB or more SSD |
| Network | 1 NIC | 2 or more NICs |

Supported virtualization platforms: VMware Workstation Pro/Player, VirtualBox,
Proxmox VE, and Hyper-V.

---

## Virtual Machines

| VM Name | OS | Purpose | RAM | Storage |
|---------|----|---------|-----|---------|
| Splunk-Server | Ubuntu 22.04 | SIEM and log analysis | 8 GB | 100 GB |
| DC01 | Windows Server 2019 | Active Directory | 4 GB | 60 GB |
| WIN10-PC | Windows 10 | Victim workstation | 4 GB | 50 GB |
| Ubuntu-Server | Ubuntu 22.04 | Linux target | 2 GB | 40 GB |
| pfSense | FreeBSD | Firewall and router | 1 GB | 10 GB |
| Kali-Attacker | Kali Linux | Attack simulation | 4 GB | 50 GB |

---

## Documentation

| Document | Description |
|----------|-------------|
| [01 - Lab Setup](docs/01-Lab-Setup.md) | Initial environment and network configuration |
| [02 - SIEM Installation](docs/02-SIEM-Installation.md) | Splunk and Elastic Stack deployment |
| [03 - Log Collection](docs/03-Log-Collection.md) | Forwarders, Sysmon, and Beats configuration |
| [04 - Detection Rules](docs/04-Detection-Rules.md) | Custom alerts and detection queries |
| [05 - Attack Simulation](docs/05-Attack-Simulation.md) | Adversary emulation exercises |
| [06 - Incident Response Case Study](docs/06-Incident-Response-Case-Study.md) | Worked investigation: LSASS credential dumping (T1003.001) |

---

## Credential Handling

This lab does not store credentials in version-controlled configuration files.
Beats agents read secrets from the local keystore at runtime, and configuration
files reference variables (for example `${ES_PWD}`) rather than plaintext
passwords. Provisioning steps are documented in
[03 - Log Collection](docs/03-Log-Collection.md). The Linux setup script
(`scripts/setup-elastic-agent.sh`) requires the Elasticsearch password to be
supplied via environment variable or prompt and writes it to the keystore;
it never embeds the secret in a config file.

This is a deliberate practice: keeping secrets out of repository history is a
baseline credential-hygiene requirement, and the lab is configured to reflect
that.

---

## Quick Start

1. Clone the repository:

   ```bash
   git clone https://github.com/RosiCastellano/SOC-Analyst-Home-Lab.git
   cd SOC-Analyst-Home-Lab
   ```

2. Build the virtual machines following the
   [Lab Setup Guide](docs/01-Lab-Setup.md).

3. Deploy a SIEM using the
   [SIEM Installation Guide](docs/02-SIEM-Installation.md).

4. Configure log collection with the
   [Log Collection Guide](docs/03-Log-Collection.md), including keystore
   provisioning and the GeoIP ingest pipeline.

5. Implement detections from the
   [Detection Rules Guide](docs/04-Detection-Rules.md).

6. Validate detections with the
   [Attack Simulation Guide](docs/05-Attack-Simulation.md), then document an
   investigation following the
   [Incident Response Case Study](docs/06-Incident-Response-Case-Study.md).

---

## Tools and Technologies

**SIEM and log management:** Splunk Enterprise (free license), Elastic Stack
(Elasticsearch, Logstash, Kibana), Wazuh.

**Log collection and forwarding:** Splunk Universal Forwarder, Winlogbeat,
Filebeat, Sysmon, Wazuh Agent.

**Network security monitoring:** Zeek, Suricata, Wireshark.

**Threat intelligence:** MISP, OpenCTI, Abuse.ch feeds.

**Attack simulation:** Atomic Red Team, MITRE Caldera, Metasploit Framework.

---

## Detection Use Cases

| ID | Use Case | MITRE ATT&CK | Splunk | Elastic | Status |
|----|----------|--------------|--------|---------|--------|
| UC-001 | Brute Force Authentication | T1110 | Yes | Yes | Implemented |
| UC-002 | Suspicious PowerShell Execution | T1059.001 | Yes | Yes | Implemented |
| UC-003 | LSASS Memory Access | T1003.001 | Yes | Yes | Implemented |
| UC-004 | Scheduled Task Creation | T1053.005 | Yes | Yes | Implemented |
| UC-005 | Registry Run Key Modification | T1547.001 | Yes | Yes | Implemented |
| UC-006 | Mimikatz Execution | T1003 | Yes | Yes | Implemented |
| UC-007 | Lateral Movement via PsExec | T1570 | Yes | Testing | In progress |
| UC-008 | Data Exfiltration Detection | T1041 | Planned | Planned | Planned |

Detection content lives in `detection-rules/`. Splunk searches are in
`splunk-queries/`; vendor-agnostic Sigma rules are in `sigma-rules/`.

---

## Repository Structure

```
SOC-Analyst-Home-Lab/
|-- README.md
|-- LICENSE
|-- docs/
|   |-- 01-Lab-Setup.md
|   |-- 02-SIEM-Installation.md
|   |-- 03-Log-Collection.md
|   |-- 04-Detection-Rules.md
|   |-- 05-Attack-Simulation.md
|   |-- 06-Incident-Response-Case-Study.md
|-- configs/
|   |-- sysmon-config.xml
|   |-- winlogbeat.yml
|   |-- filebeat.yml
|   |-- suricata.yaml
|   |-- geoip-info-pipeline.json
|-- detection-rules/
|   |-- splunk-queries/
|   |   |-- authentication-attacks.spl
|   |   |-- powershell-suspicious.spl
|   |   |-- credential-dumping.spl
|   |-- sigma-rules/
|       |-- windows-credential-access.yml
|       |-- windows-persistence.yml
|-- scripts/
|   |-- install-sysmon.ps1
|   |-- deploy-splunk-forwarder.ps1
|   |-- setup-elastic-agent.sh
|-- screenshots/
```

---

## Skills Demonstrated

- SIEM administration across Splunk and the Elastic Stack.
- Windows, Linux, and network log analysis and investigation.
- Detection engineering: authoring and tuning rules, reducing false positives,
  and mapping coverage to MITRE ATT&CK.
- Incident response: alert triage, scoping, containment, eradication, and
  documented root-cause analysis.
- Network security monitoring with Suricata and Zeek.
- Secure configuration practices, including keystore-based secret management.

---

## Safety and Usage Notice

This repository contains adversary simulation procedures and references to
offensive tooling for the sole purpose of testing defensive detections. All
techniques are publicly documented in the MITRE ATT&CK framework and the Atomic
Red Team project. Run these procedures only against systems you own, in an
isolated lab environment, with network segmentation in place. Never execute
them against production systems or networks you are not explicitly authorized to
test. See the safety section of the
[Attack Simulation Guide](docs/05-Attack-Simulation.md) before running any
exercise.

---

## Resources

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Sigma Rules Repository](https://github.com/SigmaHQ/sigma)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [Sysmon Configuration Reference](https://github.com/SwiftOnSecurity/sysmon-config)
- [Splunk Fundamentals 1 (free)](https://www.splunk.com/en_us/training/free-courses/splunk-fundamentals-1.html)
- [Elastic Training (free)](https://www.elastic.co/training/free)

---

## License

Released under the MIT License. See [LICENSE](LICENSE) for full terms.

---

## Author

Maintained by [RosiCastellano](https://github.com/RosiCastellano).

---

## Acknowledgments

- SwiftOnSecurity for the Sysmon configuration baseline.
- The SigmaHQ project for detection rule standards.
- The MITRE ATT&CK and Atomic Red Team projects.
