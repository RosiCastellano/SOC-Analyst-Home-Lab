#!/bin/bash

# ======================== SOC Analyst Home Lab ========================
# Elastic Agent / Filebeat Setup Script for Linux
# Repository: https://github.com/RosiCastellano/SOC-Analyst-Home-Lab
# ======================================================================

set -e

# Configuration - Update these values
ELASTIC_HOST="10.0.0.10"
ELASTIC_PORT="9200"
KIBANA_PORT="5601"
ELASTIC_USER="elastic"
ELASTIC_PASS="CHANGE_ME"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
    else
        log_error "Cannot detect OS"
        exit 1
    fi
    log_info "Detected OS: $OS $VERSION"
}

install_prerequisites() {
    log_info "Installing prerequisites..."
    
    case $OS in
        ubuntu|debian)
            apt-get update
            apt-get install -y curl wget apt-transport-https gnupg2
            ;;
        centos|rhel|fedora)
            yum install -y curl wget
            ;;
        *)
            log_error "Unsupported OS: $OS"
            exit 1
            ;;
    esac
}

add_elastic_repo() {
    log_info "Adding Elastic repository..."
    
    case $OS in
        ubuntu|debian)
            wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
            echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | tee /etc/apt/sources.list.d/elastic-8.x.list
            apt-get update
            ;;
        centos|rhel|fedora)
            rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch
            cat > /etc/yum.repos.d/elastic.repo << EOF
[elastic-8.x]
name=Elastic repository for 8.x packages
baseurl=https://artifacts.elastic.co/packages/8.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=1
autorefresh=1
type=rpm-md
EOF
            ;;
    esac
}

install_filebeat() {
    log_info "Installing Filebeat..."
    
    case $OS in
        ubuntu|debian)
            apt-get install -y filebeat
            ;;
        centos|rhel|fedora)
            yum install -y filebeat
            ;;
    esac
    
    log_info "Filebeat installed successfully"
}

configure_filebeat() {
    log_info "Configuring Filebeat..."
    
    # Backup original config
    cp /etc/filebeat/filebeat.yml /etc/filebeat/filebeat.yml.bak
    
    # Check if custom config exists in repo
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    CUSTOM_CONFIG="$SCRIPT_DIR/../configs/filebeat.yml"
    
    if [ -f "$CUSTOM_CONFIG" ]; then
        log_info "Using custom configuration from repository"
        cp "$CUSTOM_CONFIG" /etc/filebeat/filebeat.yml
    else
        log_info "Generating configuration..."
        cat > /etc/filebeat/filebeat.yml << EOF
# ======================== SOC Analyst Home Lab ========================
# Filebeat Configuration - Auto-generated
# ======================================================================

filebeat.inputs:

# System authentication logs
- type: log
  enabled: true
  paths:
    - /var/log/auth.log
    - /var/log/secure
  fields:
    log_type: authentication
  fields_under_root: true

# Syslog
- type: log
  enabled: true
  paths:
    - /var/log/syslog
    - /var/log/messages
  fields:
    log_type: syslog
  fields_under_root: true

# Audit logs
- type: log
  enabled: true
  paths:
    - /var/log/audit/audit.log
  fields:
    log_type: audit
  fields_under_root: true

# Web server logs
- type: log
  enabled: true
  paths:
    - /var/log/apache2/*.log
    - /var/log/nginx/*.log
    - /var/log/httpd/*.log
  fields:
    log_type: web
  fields_under_root: true

# Processors
processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
  - add_cloud_metadata: ~

# Elasticsearch Output
output.elasticsearch:
  hosts: ["${ELASTIC_HOST}:${ELASTIC_PORT}"]
  protocol: "https"
  username: "${ELASTIC_USER}"
  password: "${ELASTIC_PASS}"
  ssl.verification_mode: "none"

# Kibana
setup.kibana:
  host: "${ELASTIC_HOST}:${KIBANA_PORT}"
  protocol: "https"
  username: "${ELASTIC_USER}"
  password: "${ELASTIC_PASS}"
  ssl.verification_mode: "none"

# Dashboards
setup.dashboards.enabled: true

# Logging
logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: 7
EOF
    fi
    
    # Update password placeholder
    sed -i "s/CHANGE_ME/${ELASTIC_PASS}/g" /etc/filebeat/filebeat.yml
    
    log_info "Configuration complete"
}

enable_filebeat_modules() {
    log_info "Enabling Filebeat modules..."
    
    filebeat modules enable system
    filebeat modules enable auditd
    
    log_info "Modules enabled: system, auditd"
}

setup_auditd() {
    log_info "Setting up auditd for enhanced logging..."
    
    # Install auditd if not present
    case $OS in
        ubuntu|debian)
            apt-get install -y auditd audispd-plugins
            ;;
        centos|rhel|fedora)
            yum install -y audit
            ;;
    esac
    
    # Add security-focused audit rules
    cat > /etc/audit/rules.d/soc-lab.rules << 'EOF'
# SOC Analyst Home Lab - Audit Rules

# Delete all existing rules
-D

# Set buffer size
-b 8192

# Failure mode (1=printk, 2=panic)
-f 1

# Log all executed commands
-a always,exit -F arch=b64 -S execve -k command_execution
-a always,exit -F arch=b32 -S execve -k command_execution

# Monitor authentication files
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/group -p wa -k group_changes
-w /etc/gshadow -p wa -k gshadow_changes

# Monitor sudoers
-w /etc/sudoers -p wa -k sudoers_changes
-w /etc/sudoers.d/ -p wa -k sudoers_changes

# Monitor SSH configuration
-w /etc/ssh/sshd_config -p wa -k sshd_config

# Monitor cron
-w /etc/crontab -p wa -k cron_changes
-w /etc/cron.d/ -p wa -k cron_changes
-w /var/spool/cron/ -p wa -k cron_changes

# Monitor network configuration
-w /etc/hosts -p wa -k hosts_changes
-w /etc/network/ -p wa -k network_changes

# Monitor kernel modules
-w /sbin/insmod -p x -k module_insertion
-w /sbin/rmmod -p x -k module_removal
-w /sbin/modprobe -p x -k module_load

# Monitor user/group tools
-w /usr/sbin/useradd -p x -k user_modification
-w /usr/sbin/userdel -p x -k user_modification
-w /usr/sbin/usermod -p x -k user_modification
-w /usr/sbin/groupadd -p x -k group_modification
-w /usr/sbin/groupdel -p x -k group_modification
-w /usr/sbin/groupmod -p x -k group_modification

# Monitor privilege escalation
-w /bin/su -p x -k privilege_escalation
-w /usr/bin/sudo -p x -k privilege_escalation

# Lock the audit configuration
-e 2
EOF

    # Restart auditd
    systemctl restart auditd
    
    log_info "Auditd configured with security rules"
}

test_connection() {
    log_info "Testing connection to Elasticsearch..."
    
    response=$(curl -s -o /dev/null -w "%{http_code}" -k -u "${ELASTIC_USER}:${ELASTIC_PASS}" "https://${ELASTIC_HOST}:${ELASTIC_PORT}")
    
    if [ "$response" = "200" ]; then
        log_info "Successfully connected to Elasticsearch"
    else
        log_warn "Could not connect to Elasticsearch (HTTP $response)"
        log_warn "Please verify the server is running and credentials are correct"
    fi
}

start_filebeat() {
    log_info "Starting Filebeat..."
    
    # Test configuration
    filebeat test config
    filebeat test output
    
    # Enable and start service
    systemctl daemon-reload
    systemctl enable filebeat
    systemctl start filebeat
    
    log_info "Filebeat started"
    
    # Show status
    systemctl status filebeat --no-pager
}

show_summary() {
    echo ""
    echo "========================================"
    echo "  Installation Complete!"
    echo "========================================"
    echo ""
    echo "Filebeat is now configured to send logs to:"
    echo "  Elasticsearch: ${ELASTIC_HOST}:${ELASTIC_PORT}"
    echo "  Kibana: ${ELASTIC_HOST}:${KIBANA_PORT}"
    echo ""
    echo "Logs being collected:"
    echo "  - /var/log/auth.log (authentication)"
    echo "  - /var/log/syslog (system)"
    echo "  - /var/log/audit/audit.log (auditd)"
    echo "  - /var/log/apache2/*.log (web)"
    echo "  - /var/log/nginx/*.log (web)"
    echo ""
    echo "Useful commands:"
    echo "  Check status:  systemctl status filebeat"
    echo "  View logs:     tail -f /var/log/filebeat/filebeat"
    echo "  Test config:   filebeat test config"
    echo "  Test output:   filebeat test output"
    echo ""
}

# ==================== Main Execution ====================

main() {
    echo "========================================"
    echo "  SOC Analyst Home Lab"
    echo "  Elastic Agent Setup Script"
    echo "========================================"
    echo ""
    
    check_root
    detect_os
    install_prerequisites
    add_elastic_repo
    install_filebeat
    configure_filebeat
    enable_filebeat_modules
    setup_auditd
    test_connection
    start_filebeat
    show_summary
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --elastic-host)
            ELASTIC_HOST="$2"
            shift 2
            ;;
        --elastic-pass)
            ELASTIC_PASS="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --elastic-host HOST   Elasticsearch server IP (default: 10.0.0.10)"
            echo "  --elastic-pass PASS   Elasticsearch password"
            echo "  --help                Show this help message"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

main
