# 02 - SIEM Installation Guide

This guide covers the installation and configuration of SIEM platforms for your SOC home lab.

---

## SIEM Options

| Platform | License | Daily Limit | Best For |
|----------|---------|-------------|----------|
| Splunk Enterprise | Free | 500 MB/day | Industry experience |
| Elastic Stack (ELK) | Open Source | Unlimited | Flexibility |
| Wazuh | Open Source | Unlimited | XDR capabilities |

---

## Option 1: Splunk Enterprise (Recommended)

### Why Splunk?
- Industry-leading SIEM platform
- Widely used in enterprise environments
- Excellent documentation and community
- Free license for learning (500 MB/day)

### System Requirements
- Ubuntu 22.04 LTS
- 8 GB RAM minimum
- 100 GB storage
- 4 CPU cores

### Installation Steps

#### Step 1: Download Splunk

1. Create account at [Splunk.com](https://www.splunk.com/)
2. Download Splunk Enterprise (.deb package)
3. Transfer to your Splunk server

#### Step 2: Install Splunk

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y wget curl net-tools

# Install Splunk (adjust filename as needed)
sudo dpkg -i splunk-9.1.0-linux-2.6-amd64.deb

# Start Splunk and accept license
sudo /opt/splunk/bin/splunk start --accept-license

# Enable boot start
sudo /opt/splunk/bin/splunk enable boot-start
```

#### Step 3: Initial Configuration

1. Access web interface: `http://10.0.0.10:8000`
2. Create admin account
3. Configure receiving:
   - Settings → Forwarding and receiving
   - Configure receiving → New Receiving Port
   - Port: `9997`

#### Step 4: Install Essential Apps

Navigate to **Apps → Find More Apps** and install:

- Splunk Common Information Model (CIM)
- Splunk Security Essentials
- Sysmon App for Splunk
- Windows Security Monitoring

#### Step 5: Create Indexes

Go to **Settings → Indexes → New Index**:

| Index Name | Purpose | Max Size |
|------------|---------|----------|
| windows | Windows event logs | 50 GB |
| sysmon | Sysmon events | 50 GB |
| linux | Linux logs | 20 GB |
| firewall | pfSense logs | 20 GB |
| network | Zeek/Suricata | 30 GB |

---

## Option 2: Elastic Stack (ELK)

### Components
- **Elasticsearch** - Search and analytics engine
- **Logstash** - Data processing pipeline
- **Kibana** - Visualization platform

### Installation Steps

#### Step 1: Install Prerequisites

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Java
sudo apt install -y openjdk-17-jdk

# Add Elastic GPG key
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg

# Add repository
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list

sudo apt update
```

#### Step 2: Install Elasticsearch

```bash
# Install Elasticsearch
sudo apt install -y elasticsearch

# Configure Elasticsearch
sudo nano /etc/elasticsearch/elasticsearch.yml
```

Add/modify these settings:
```yaml
cluster.name: soc-lab
node.name: node-1
network.host: 0.0.0.0
discovery.type: single-node
xpack.security.enabled: true
xpack.security.enrollment.enabled: true
```

```bash
# Start Elasticsearch
sudo systemctl daemon-reload
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch

# Generate passwords (save these!)
sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic
```

#### Step 3: Install Kibana

```bash
# Install Kibana
sudo apt install -y kibana

# Configure Kibana
sudo nano /etc/kibana/kibana.yml
```

Add/modify:
```yaml
server.port: 5601
server.host: "0.0.0.0"
elasticsearch.hosts: ["http://localhost:9200"]
```

```bash
# Generate enrollment token
sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana

# Start Kibana
sudo systemctl enable kibana
sudo systemctl start kibana
```

#### Step 4: Install Logstash

```bash
# Install Logstash
sudo apt install -y logstash

# Create configuration directory
sudo mkdir -p /etc/logstash/conf.d
```

Create input configuration:
```bash
sudo nano /etc/logstash/conf.d/01-inputs.conf
```

```ruby
input {
  beats {
    port => 5044
  }
  
  tcp {
    port => 5514
    type => "syslog"
  }
  
  udp {
    port => 5514
    type => "syslog"
  }
}
```

Create output configuration:
```bash
sudo nano /etc/logstash/conf.d/99-outputs.conf
```

```ruby
output {
  elasticsearch {
    hosts => ["localhost:9200"]
    user => "elastic"
    password => "YOUR_PASSWORD_HERE"
    index => "%{[@metadata][beat]}-%{+YYYY.MM.dd}"
  }
}
```

```bash
# Start Logstash
sudo systemctl enable logstash
sudo systemctl start logstash
```

#### Step 5: Access Kibana

1. Navigate to `http://10.0.0.10:5601`
2. Login with elastic user credentials
3. Configure index patterns

---

## Option 3: Wazuh

### Why Wazuh?
- Free and open source XDR platform
- Built-in SIEM, IDS, and vulnerability detection
- Active response capabilities
- Great for compliance

### Quick Installation

```bash
# Download and run installer
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash wazuh-install.sh -a
```

The installer will:
- Install Wazuh indexer
- Install Wazuh server
- Install Wazuh dashboard
- Generate credentials

Access dashboard at `https://10.0.0.10` with generated credentials.

---

## Firewall Configuration

Ensure these ports are open on your SIEM server:

| Port | Protocol | Service |
|------|----------|---------|
| 8000 | TCP | Splunk Web |
| 8089 | TCP | Splunk Management |
| 9997 | TCP | Splunk Receiving |
| 5601 | TCP | Kibana |
| 9200 | TCP | Elasticsearch |
| 5044 | TCP | Logstash Beats |
| 443 | TCP | Wazuh Dashboard |

```bash
# UFW example
sudo ufw allow 8000/tcp
sudo ufw allow 9997/tcp
sudo ufw allow 5601/tcp
sudo ufw allow 5044/tcp
```

---

## Verification

### Splunk
```bash
# Check service status
sudo /opt/splunk/bin/splunk status

# Check listening ports
sudo netstat -tlnp | grep splunk
```

### Elastic Stack
```bash
# Check Elasticsearch
curl -X GET "localhost:9200/_cluster/health?pretty" -u elastic

# Check Kibana
sudo systemctl status kibana

# Check Logstash
sudo systemctl status logstash
```

### Wazuh
```bash
# Check all services
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-indexer
sudo systemctl status wazuh-dashboard
```

---

## Next Steps

Once your SIEM is installed, proceed to:
- [03 - Log Collection](03-Log-Collection.md)
