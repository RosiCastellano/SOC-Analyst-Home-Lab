<#
.SYNOPSIS
    Deploys and configures Splunk Universal Forwarder for SOC Analyst Home Lab

.DESCRIPTION
    This script installs Splunk Universal Forwarder, configures inputs
    for Windows logs and Sysmon, and sets up forwarding to the Splunk server.

.NOTES
    Repository: https://github.com/RosiCastellano/SOC-Analyst-Home-Lab
    Requires: Administrator privileges
#>

#Requires -RunAsAdministrator

param(
    [Parameter(Mandatory=$true)]
    [string]$SplunkServer,
    
    [int]$SplunkPort = 9997,
    
    [string]$InstallerPath = "",
    
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"

# Configuration
$SplunkHome = "C:\Program Files\SplunkUniversalForwarder"
$LocalDir = "$SplunkHome\etc\system\local"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] [$Level] $Message"
}

function Test-SplunkInstalled {
    return Test-Path "$SplunkHome\bin\splunk.exe"
}

function Install-SplunkForwarder {
    Write-Log "Installing Splunk Universal Forwarder..."
    
    if ([string]::IsNullOrEmpty($InstallerPath)) {
        Write-Log "Please download the Splunk Universal Forwarder from:" "INFO"
        Write-Log "https://www.splunk.com/en_us/download/universal-forwarder.html" "INFO"
        Write-Log "Then run this script with -InstallerPath parameter" "INFO"
        throw "Installer path required"
    }
    
    if (!(Test-Path $InstallerPath)) {
        throw "Installer not found: $InstallerPath"
    }
    
    # Generate random password for initial setup
    $randomPassword = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 12 | ForEach-Object {[char]$_})
    
    # Silent install
    $installArgs = @(
        "/i `"$InstallerPath`"",
        "RECEIVING_INDEXER=`"$SplunkServer`:$SplunkPort`"",
        "AGREETOLICENSE=yes",
        "SPLUNKPASSWORD=`"$randomPassword`"",
        "LAUNCHSPLUNK=0",
        "/quiet"
    )
    
    Write-Log "Running installer..."
    $process = Start-Process -FilePath "msiexec.exe" -ArgumentList ($installArgs -join " ") -Wait -PassThru
    
    if ($process.ExitCode -eq 0) {
        Write-Log "Installation completed" "SUCCESS"
        Write-Log "Initial password: $randomPassword (change this!)" "WARNING"
    }
    else {
        throw "Installation failed with exit code: $($process.ExitCode)"
    }
}

function Configure-Inputs {
    Write-Log "Configuring inputs..."
    
    $inputsConf = @"
# ======================== SOC Analyst Home Lab ========================
# Splunk Universal Forwarder Inputs Configuration
# Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
# ======================================================================

[default]
host = $env:COMPUTERNAME

# ==================== Windows Security Events =========================
[WinEventLog://Security]
disabled = 0
index = windows
sourcetype = WinEventLog:Security
renderXml = false

# ==================== Windows System Events ===========================
[WinEventLog://System]
disabled = 0
index = windows
sourcetype = WinEventLog:System

# ==================== Windows Application Events ======================
[WinEventLog://Application]
disabled = 0
index = windows
sourcetype = WinEventLog:Application

# ==================== Sysmon Events ===================================
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = sysmon
sourcetype = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
renderXml = true

# ==================== PowerShell Events ===============================
[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = 0
index = windows
sourcetype = WinEventLog:PowerShell

[WinEventLog://Windows PowerShell]
disabled = 0
index = windows
sourcetype = WinEventLog:PowerShell

# ==================== Windows Defender ================================
[WinEventLog://Microsoft-Windows-Windows Defender/Operational]
disabled = 0
index = windows
sourcetype = WinEventLog:Defender

# ==================== Task Scheduler ==================================
[WinEventLog://Microsoft-Windows-TaskScheduler/Operational]
disabled = 0
index = windows
sourcetype = WinEventLog:TaskScheduler

# ==================== DNS Client ======================================
[WinEventLog://Microsoft-Windows-DNS-Client/Operational]
disabled = 0
index = windows
sourcetype = WinEventLog:DNS

# ==================== WMI Activity ====================================
[WinEventLog://Microsoft-Windows-WMI-Activity/Operational]
disabled = 0
index = windows
sourcetype = WinEventLog:WMI
"@

    if (!(Test-Path $LocalDir)) {
        New-Item -ItemType Directory -Path $LocalDir -Force | Out-Null
    }
    
    Set-Content -Path "$LocalDir\inputs.conf" -Value $inputsConf
    Write-Log "inputs.conf created"
}

function Configure-Outputs {
    Write-Log "Configuring outputs to $SplunkServer`:$SplunkPort..."
    
    $outputsConf = @"
# ======================== SOC Analyst Home Lab ========================
# Splunk Universal Forwarder Outputs Configuration
# Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
# ======================================================================

[tcpout]
defaultGroup = splunk-indexers

[tcpout:splunk-indexers]
server = $SplunkServer`:$SplunkPort

[tcpout-server://$SplunkServer`:$SplunkPort]
"@

    Set-Content -Path "$LocalDir\outputs.conf" -Value $outputsConf
    Write-Log "outputs.conf created"
}

function Start-SplunkForwarder {
    Write-Log "Starting Splunk Universal Forwarder..."
    
    $splunkCmd = "$SplunkHome\bin\splunk.exe"
    
    # Start the service
    & $splunkCmd start
    
    # Enable boot start
    & $splunkCmd enable boot-start
    
    Write-Log "Forwarder started and configured for boot start"
}

function Restart-SplunkForwarder {
    Write-Log "Restarting Splunk Universal Forwarder..."
    
    $splunkCmd = "$SplunkHome\bin\splunk.exe"
    & $splunkCmd restart
    
    Write-Log "Forwarder restarted"
}

function Uninstall-SplunkForwarder {
    Write-Log "Uninstalling Splunk Universal Forwarder..."
    
    # Stop service first
    $splunkCmd = "$SplunkHome\bin\splunk.exe"
    if (Test-Path $splunkCmd) {
        & $splunkCmd stop
    }
    
    # Uninstall via registry
    $uninstallString = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | 
        Where-Object { $_.DisplayName -like "*Splunk*Universal*" } |
        Select-Object -ExpandProperty UninstallString
    
    if ($uninstallString) {
        Start-Process -FilePath "msiexec.exe" -ArgumentList "/x $uninstallString /quiet" -Wait
        Write-Log "Uninstallation completed"
    }
    else {
        Write-Log "Uninstall string not found" "WARNING"
    }
}

function Test-ForwarderConnection {
    Write-Log "Testing connection to Splunk server..."
    
    $tcpTest = Test-NetConnection -ComputerName $SplunkServer -Port $SplunkPort -WarningAction SilentlyContinue
    
    if ($tcpTest.TcpTestSucceeded) {
        Write-Log "Connection to $SplunkServer`:$SplunkPort successful" "SUCCESS"
    }
    else {
        Write-Log "Cannot connect to $SplunkServer`:$SplunkPort" "WARNING"
        Write-Log "Ensure the Splunk server is running and firewall allows connection" "WARNING"
    }
}

# Main execution
try {
    Write-Log "=" * 60
    Write-Log "SOC Analyst Home Lab - Splunk Forwarder Deployment"
    Write-Log "=" * 60
    
    if ($Uninstall) {
        Uninstall-SplunkForwarder
        exit 0
    }
    
    # Test connection first
    Test-ForwarderConnection
    
    if (Test-SplunkInstalled) {
        Write-Log "Splunk Universal Forwarder already installed"
        Write-Log "Updating configuration..."
        Configure-Inputs
        Configure-Outputs
        Restart-SplunkForwarder
    }
    else {
        Install-SplunkForwarder
        Configure-Inputs
        Configure-Outputs
        Start-SplunkForwarder
    }
    
    Write-Log "Deployment completed successfully!" "SUCCESS"
    Write-Log ""
    Write-Log "Next steps:"
    Write-Log "1. Verify data in Splunk: index=windows OR index=sysmon"
    Write-Log "2. Check forwarder status: splunk list forward-server"
    Write-Log "3. Ensure indexes exist on Splunk server: windows, sysmon"
}
catch {
    Write-Log "Error: $_" "ERROR"
    exit 1
}
