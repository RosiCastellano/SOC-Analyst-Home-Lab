# 01 - Lab Setup Guide

This guide covers the initial setup of your SOC Analyst Home Lab environment.

---

## Prerequisites

Before starting, ensure you have:

- A host machine with sufficient resources (see requirements below)
- Virtualization software installed
- ISO images for required operating systems
- Stable internet connection for downloads

---

## Hardware Requirements

### Minimum Configuration
| Component | Specification |
|-----------|--------------|
| CPU | Intel i5/AMD Ryzen 5 (4 cores) |
| RAM | 16 GB DDR4 |
| Storage | 256 GB SSD |
| Network | 1 Gigabit NIC |

### Recommended Configuration
| Component | Specification |
|-----------|--------------|
| CPU | Intel i7/AMD Ryzen 7 (8+ cores) |
| RAM | 32-64 GB DDR4 |
| Storage | 500 GB+ NVMe SSD |
| Network | 2 Gigabit NICs |

---

## Virtualization Platform Setup

### Option 1: VMware Workstation Pro

1. Download from [VMware](https://www.vmware.com/products/workstation-pro.html)
2. Install with default settings
3. Configure virtual networks:
   - **VMnet1** (Host-only): 10.0.0.0/24 - Management
   - **VMnet2** (Host-only): 10.0.1.0/24 - Victim Network
   - **VMnet3** (Host-only): 10.0.2.0/24 - Attacker Network

### Option 2: VirtualBox (Free)

1. Download from [VirtualBox](https://www.virtualbox.org/)
2. Install with default settings
3. Configure host-only networks:
   ```
   File → Host Network Manager → Create
   ```
   - **vboxnet0**: 10.0.0.0/24
   - **vboxnet1**: 10.0.1.0/24
   - **vboxnet2**: 10.0.2.0/24

### Option 3: Proxmox VE (Recommended for Dedicated Hardware)

1. Download ISO from [Proxmox](https://www.proxmox.com/en/downloads)
2. Install on dedicated hardware
3. Create Linux bridges for network segmentation

---

## Required ISO Images

Download the following ISO images:

| OS | Source | Purpose |
|----|--------|---------|
| Ubuntu 22.04 Server | [Ubuntu](https://ubuntu.com/download/server) | Splunk, Linux targets |
| Windows 10 Enterprise | [Microsoft Eval Center](https://www.microsoft.com/en-us/evalcenter/) | Workstation |
| Windows Server 2019 | [Microsoft Eval Center](https://www.microsoft.com/en-us/evalcenter/) | Domain Controller |
| Kali Linux | [Kali](https://www.kali.org/get-kali/) | Attacker machine |
| pfSense | [pfSense](https://www.pfsense.org/download/) | Firewall |

---

## Network Architecture

```
┌────────────────────────────────────────────────────────────┐
│                    HOST MACHINE                            │
│  ┌──────────────────────────────────────────────────────┐  │
│  │                 VIRTUAL NETWORKS                     │  │
│  │                                                      │  │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐     │  │
│  │  │ Management  │ │   Victim    │ │  Attacker   │     │  │
│  │  │ 10.0.0.0/24 │ │ 10.0.1.0/24 │ │ 10.0.2.0/24 │     │  │
│  │  └─────────────┘ └─────────────┘ └─────────────┘     │  │
│  │        │               │               │             │  │
│  │        └───────────────┼───────────────┘             │  │
│  │                        │                             │  │
│  │                  ┌─────────────┐                     │  │
│  │                  │  pfSense    │                     │  │
│  │                  │  (Router)   │                     │  │
│  │                  └─────────────┘                     │  │
│  │                        │                             │  │
│  │                  ┌─────────────┐                     │  │
│  │                  │   NAT/WAN   │                     │  │
│  │                  └─────────────┘                     │  │
│  └──────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────┘
```

---

## Virtual Machine Creation

### VM 1: Splunk Server (Ubuntu 22.04)

**Specifications:**
- CPU: 4 cores
- RAM: 8 GB
- Storage: 100 GB
- Network: Management (10.0.0.10)

**Installation Steps:**
1. Create new VM with Ubuntu Server ISO
2. Install Ubuntu with minimal installation
3. Set static IP:
   ```bash
   sudo nano /etc/netplan/00-installer-config.yaml
   ```
   ```yaml
   network:
     version: 2
     ethernets:
       ens33:
         addresses:
           - 10.0.0.10/24
         gateway4: 10.0.0.1
         nameservers:
           addresses:
             - 8.8.8.8
             - 8.8.4.4
   ```
   ```bash
   sudo netplan apply
   ```

### VM 2: Domain Controller (Windows Server 2019)

**Specifications:**
- CPU: 2 cores
- RAM: 4 GB
- Storage: 60 GB
- Network: Victim Network (10.0.1.20)

**Installation Steps:**
1. Create new VM with Windows Server ISO
2. Install Windows Server with Desktop Experience
3. Set static IP: 10.0.1.20
4. Install Active Directory Domain Services
5. Promote to Domain Controller
   - Domain: `soclab.local`
   - NetBIOS: `SOCLAB`

### VM 3: Windows 10 Workstation

**Specifications:**
- CPU: 2 cores
- RAM: 4 GB
- Storage: 50 GB
- Network: Victim Network (10.0.1.10)

**Installation Steps:**
1. Create new VM with Windows 10 ISO
2. Install Windows 10 Enterprise
3. Set static IP: 10.0.1.10
4. Join to domain `soclab.local`
5. Install Sysmon (see configs/sysmon-config.xml)

### VM 4: Ubuntu Server (Target)

**Specifications:**
- CPU: 2 cores
- RAM: 2 GB
- Storage: 40 GB
- Network: Victim Network (10.0.1.30)

**Installation Steps:**
1. Create new VM with Ubuntu Server ISO
2. Install with OpenSSH server
3. Set static IP: 10.0.1.30
4. Install vulnerable applications for testing

### VM 5: Kali Linux (Attacker)

**Specifications:**
- CPU: 2 cores
- RAM: 4 GB
- Storage: 50 GB
- Network: Attacker Network (10.0.2.10)

**Installation Steps:**
1. Create new VM with Kali ISO
2. Install with default settings
3. Set static IP: 10.0.2.10
4. Update and upgrade:
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```

### VM 6: pfSense (Firewall/Router)

**Specifications:**
- CPU: 1 core
- RAM: 1 GB
- Storage: 10 GB
- Network Adapters:
  - WAN: NAT/Bridged
  - LAN1: Management (10.0.0.1)
  - LAN2: Victim (10.0.1.1)
  - LAN3: Attacker (10.0.2.1)

---

## Post-Installation Checklist

- [ ] All VMs can ping their gateway
- [ ] Splunk server is accessible via web interface
- [ ] Domain Controller is functional
- [ ] Windows 10 is joined to domain
- [ ] Kali can reach victim network (when allowed)
- [ ] pfSense firewall rules are configured
- [ ] Snapshots created for all VMs (clean state)

---

## Troubleshooting

### Network Connectivity Issues
1. Verify virtual network adapter assignments
2. Check IP configurations
3. Verify pfSense routing tables
4. Test with ping between VMs

### Performance Issues
1. Reduce VMs running simultaneously
2. Increase host RAM if possible
3. Use SSD storage
4. Disable unnecessary services

---

## Next Steps

Once your lab environment is set up, proceed to:
- [02 - SIEM Installation](02-SIEM-Installation.md)
