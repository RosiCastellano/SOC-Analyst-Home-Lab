<#
.SYNOPSIS
    Installs and configures Sysmon for SOC Analyst Home Lab

.DESCRIPTION
    This script downloads Sysmon, applies the lab configuration,
    and installs it as a service.

.NOTES
    Repository: https://github.com/RosiCastellano/SOC-Analyst-Home-Lab
    Requires: Administrator privileges
#>

#Requires -RunAsAdministrator

param(
    [string]$ConfigPath = "",
    [switch]$Update,
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"

# Configuration
$SysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip"
$SwiftConfigUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
$InstallPath = "C:\Sysmon"
$LogPath = "C:\Sysmon\logs"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Write-Host $logMessage
    
    if (Test-Path $LogPath) {
        Add-Content -Path "$LogPath\install.log" -Value $logMessage
    }
}

function Test-SysmonInstalled {
    $service = Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue
    return $null -ne $service
}

function Install-Sysmon {
    Write-Log "Starting Sysmon installation..."
    
    # Create directories
    if (!(Test-Path $InstallPath)) {
        New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
        Write-Log "Created directory: $InstallPath"
    }
    
    if (!(Test-Path $LogPath)) {
        New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
        Write-Log "Created log directory: $LogPath"
    }
    
    # Download Sysmon
    Write-Log "Downloading Sysmon..."
    $zipPath = "$InstallPath\Sysmon.zip"
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $SysmonUrl -OutFile $zipPath -UseBasicParsing
        Write-Log "Sysmon downloaded successfully"
    }
    catch {
        Write-Log "Failed to download Sysmon: $_" "ERROR"
        throw
    }
    
    # Extract Sysmon
    Write-Log "Extracting Sysmon..."
    Expand-Archive -Path $zipPath -DestinationPath $InstallPath -Force
    Remove-Item $zipPath -Force
    
    # Get configuration
    if ([string]::IsNullOrEmpty($ConfigPath)) {
        # Check for local config
        $localConfig = Join-Path (Split-Path $PSScriptRoot -Parent) "configs\sysmon-config.xml"
        if (Test-Path $localConfig) {
            $ConfigPath = $localConfig
            Write-Log "Using local configuration: $ConfigPath"
        }
        else {
            # Download SwiftOnSecurity config
            Write-Log "Downloading SwiftOnSecurity configuration..."
            $ConfigPath = "$InstallPath\sysmonconfig.xml"
            Invoke-WebRequest -Uri $SwiftConfigUrl -OutFile $ConfigPath -UseBasicParsing
            Write-Log "Configuration downloaded"
        }
    }
    
    # Determine architecture
    $sysmonExe = if ([Environment]::Is64BitOperatingSystem) {
        "$InstallPath\Sysmon64.exe"
    } else {
        "$InstallPath\Sysmon.exe"
    }
    
    # Install Sysmon
    Write-Log "Installing Sysmon with configuration..."
    $installArgs = "-accepteula -i `"$ConfigPath`""
    $process = Start-Process -FilePath $sysmonExe -ArgumentList $installArgs -Wait -PassThru -NoNewWindow
    
    if ($process.ExitCode -eq 0) {
        Write-Log "Sysmon installed successfully!" "SUCCESS"
    }
    else {
        Write-Log "Sysmon installation failed with exit code: $($process.ExitCode)" "ERROR"
        throw "Installation failed"
    }
    
    # Verify installation
    Start-Sleep -Seconds 2
    if (Test-SysmonInstalled) {
        $service = Get-Service -Name "Sysmon*"
        Write-Log "Sysmon service status: $($service.Status)"
        
        # Test event generation
        $events = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 -ErrorAction SilentlyContinue
        if ($events) {
            Write-Log "Sysmon is generating events successfully"
        }
    }
}

function Update-SysmonConfig {
    Write-Log "Updating Sysmon configuration..."
    
    if ([string]::IsNullOrEmpty($ConfigPath)) {
        Write-Log "No configuration path specified" "ERROR"
        throw "Please specify a configuration file with -ConfigPath"
    }
    
    if (!(Test-Path $ConfigPath)) {
        Write-Log "Configuration file not found: $ConfigPath" "ERROR"
        throw "Configuration file not found"
    }
    
    $sysmonExe = if ([Environment]::Is64BitOperatingSystem) {
        "$InstallPath\Sysmon64.exe"
    } else {
        "$InstallPath\Sysmon.exe"
    }
    
    $updateArgs = "-c `"$ConfigPath`""
    $process = Start-Process -FilePath $sysmonExe -ArgumentList $updateArgs -Wait -PassThru -NoNewWindow
    
    if ($process.ExitCode -eq 0) {
        Write-Log "Configuration updated successfully!" "SUCCESS"
    }
    else {
        Write-Log "Configuration update failed" "ERROR"
    }
}

function Uninstall-Sysmon {
    Write-Log "Uninstalling Sysmon..."
    
    $sysmonExe = if ([Environment]::Is64BitOperatingSystem) {
        "$InstallPath\Sysmon64.exe"
    } else {
        "$InstallPath\Sysmon.exe"
    }
    
    if (Test-Path $sysmonExe) {
        $process = Start-Process -FilePath $sysmonExe -ArgumentList "-u" -Wait -PassThru -NoNewWindow
        if ($process.ExitCode -eq 0) {
            Write-Log "Sysmon uninstalled successfully" "SUCCESS"
        }
    }
    else {
        Write-Log "Sysmon executable not found" "WARNING"
    }
}

# Main execution
try {
    Write-Log "=" * 60
    Write-Log "SOC Analyst Home Lab - Sysmon Installer"
    Write-Log "=" * 60
    
    if ($Uninstall) {
        Uninstall-Sysmon
    }
    elseif ($Update) {
        Update-SysmonConfig
    }
    else {
        if (Test-SysmonInstalled) {
            Write-Log "Sysmon is already installed. Use -Update to update config or -Uninstall to remove."
        }
        else {
            Install-Sysmon
        }
    }
    
    Write-Log "Operation completed successfully" "SUCCESS"
}
catch {
    Write-Log "Error: $_" "ERROR"
    exit 1
}
