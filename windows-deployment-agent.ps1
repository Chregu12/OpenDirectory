# OpenDirectory Windows Deployment Agent
# Handles application installation on Windows devices

param(
    [Parameter(Mandatory=$true)]
    [string]$Application,
    
    [Parameter(Mandatory=$false)]
    [string]$Version = "latest",
    
    [Parameter(Mandatory=$false)]
    [string]$OpenDirectoryServer = "192.168.1.223:30055"
)

# Configuration
$LogPath = "$env:ProgramData\OpenDirectory\Logs\deployment.log"
$DeploymentPath = "$env:ProgramData\OpenDirectory\Deployments"

# Ensure directories exist
if (!(Test-Path -Path (Split-Path $LogPath))) {
    New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null
}
if (!(Test-Path -Path $DeploymentPath)) {
    New-Item -ItemType Directory -Path $DeploymentPath -Force | Out-Null
}

# Logging function
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    Write-Host $LogEntry
    Add-Content -Path $LogPath -Value $LogEntry
}

# Get system information
function Get-SystemInfo {
    $OS = Get-CimInstance -ClassName Win32_OperatingSystem
    $Computer = Get-CimInstance -ClassName Win32_ComputerSystem
    
    return @{
        Hostname = $env:COMPUTERNAME
        OS = $OS.Caption
        Version = $OS.Version
        Architecture = $OS.OSArchitecture
        Domain = $Computer.Domain
        TotalMemory = [math]::Round($Computer.TotalPhysicalMemory / 1GB, 2)
    }
}

# Application installation functions
function Install-GoogleChrome {
    Write-Log "Starting Google Chrome installation..."
    
    $DownloadUrl = "https://dl.google.com/chrome/install/googlechromestandaloneenterprise64.msi"
    $InstallerPath = "$env:TEMP\chrome_installer.msi"
    
    try {
        # Download installer
        Write-Log "Downloading Chrome installer..."
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $InstallerPath
        
        # Install silently
        Write-Log "Installing Chrome..."
        $Process = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$InstallerPath`" /quiet /norestart" -Wait -PassThru
        
        if ($Process.ExitCode -eq 0) {
            Write-Log "Chrome installation completed successfully" "SUCCESS"
            
            # Verify installation
            $ChromePath = "${env:ProgramFiles}\Google\Chrome\Application\chrome.exe"
            if (Test-Path $ChromePath) {
                $Version = (Get-ItemProperty $ChromePath).VersionInfo.FileVersion
                Write-Log "Chrome version $Version installed successfully" "SUCCESS"
                return @{ Success = $true; Version = $Version }
            }
        } else {
            Write-Log "Chrome installation failed with exit code: $($Process.ExitCode)" "ERROR"
            return @{ Success = $false; Error = "Installation failed" }
        }
    }
    catch {
        Write-Log "Chrome installation failed: $($_.Exception.Message)" "ERROR"
        return @{ Success = $false; Error = $_.Exception.Message }
    }
    finally {
        # Cleanup
        if (Test-Path $InstallerPath) {
            Remove-Item $InstallerPath -Force
        }
    }
}

function Install-VSCode {
    Write-Log "Starting Visual Studio Code installation..."
    
    $DownloadUrl = "https://code.visualstudio.com/sha/download?build=stable&os=win32-x64"
    $InstallerPath = "$env:TEMP\vscode_installer.exe"
    
    try {
        # Download installer
        Write-Log "Downloading VS Code installer..."
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $InstallerPath
        
        # Install silently
        Write-Log "Installing VS Code..."
        $Process = Start-Process -FilePath $InstallerPath -ArgumentList "/verysilent /suppressmsgboxes /mergetasks=!runcode" -Wait -PassThru
        
        if ($Process.ExitCode -eq 0) {
            Write-Log "VS Code installation completed successfully" "SUCCESS"
            
            # Verify installation
            $VSCodePath = "${env:ProgramFiles}\Microsoft VS Code\Code.exe"
            if (Test-Path $VSCodePath) {
                $Version = (Get-ItemProperty $VSCodePath).VersionInfo.FileVersion
                Write-Log "VS Code version $Version installed successfully" "SUCCESS"
                return @{ Success = $true; Version = $Version }
            }
        } else {
            Write-Log "VS Code installation failed with exit code: $($Process.ExitCode)" "ERROR"
            return @{ Success = $false; Error = "Installation failed" }
        }
    }
    catch {
        Write-Log "VS Code installation failed: $($_.Exception.Message)" "ERROR"
        return @{ Success = $false; Error = $_.Exception.Message }
    }
    finally {
        # Cleanup
        if (Test-Path $InstallerPath) {
            Remove-Item $InstallerPath -Force
        }
    }
}

function Install-DockerDesktop {
    Write-Log "Starting Docker Desktop installation..."
    
    $DownloadUrl = "https://desktop.docker.com/win/main/amd64/Docker%20Desktop%20Installer.exe"
    $InstallerPath = "$env:TEMP\docker_desktop_installer.exe"
    
    try {
        # Download installer
        Write-Log "Downloading Docker Desktop installer..."
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $InstallerPath
        
        # Install silently
        Write-Log "Installing Docker Desktop..."
        $Process = Start-Process -FilePath $InstallerPath -ArgumentList "install --quiet" -Wait -PassThru
        
        if ($Process.ExitCode -eq 0) {
            Write-Log "Docker Desktop installation completed successfully" "SUCCESS"
            
            # Docker Desktop requires restart, so we'll just verify the installation files exist
            $DockerPath = "${env:ProgramFiles}\Docker\Docker\Docker Desktop.exe"
            if (Test-Path $DockerPath) {
                $Version = (Get-ItemProperty $DockerPath).VersionInfo.FileVersion
                Write-Log "Docker Desktop version $Version installed successfully" "SUCCESS"
                Write-Log "Note: System restart may be required for Docker Desktop to function properly" "WARNING"
                return @{ Success = $true; Version = $Version; RequiresRestart = $true }
            }
        } else {
            Write-Log "Docker Desktop installation failed with exit code: $($Process.ExitCode)" "ERROR"
            return @{ Success = $false; Error = "Installation failed" }
        }
    }
    catch {
        Write-Log "Docker Desktop installation failed: $($_.Exception.Message)" "ERROR"
        return @{ Success = $false; Error = $_.Exception.Message }
    }
    finally {
        # Cleanup
        if (Test-Path $InstallerPath) {
            Remove-Item $InstallerPath -Force
        }
    }
}

function Install-MicrosoftTeams {
    Write-Log "Starting Microsoft Teams installation..."
    
    $DownloadUrl = "https://teams.microsoft.com/downloads/desktopurl?env=production&plat=windows&arch=x64&managedinstaller=true&download=true"
    $InstallerPath = "$env:TEMP\teams_installer.msi"
    
    try {
        # Download installer
        Write-Log "Downloading Teams installer..."
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $InstallerPath
        
        # Install silently
        Write-Log "Installing Teams..."
        $Process = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$InstallerPath`" /quiet /norestart" -Wait -PassThru
        
        if ($Process.ExitCode -eq 0) {
            Write-Log "Microsoft Teams installation completed successfully" "SUCCESS"
            return @{ Success = $true; Version = "Latest" }
        } else {
            Write-Log "Teams installation failed with exit code: $($Process.ExitCode)" "ERROR"
            return @{ Success = $false; Error = "Installation failed" }
        }
    }
    catch {
        Write-Log "Teams installation failed: $($_.Exception.Message)" "ERROR"
        return @{ Success = $false; Error = $_.Exception.Message }
    }
    finally {
        # Cleanup
        if (Test-Path $InstallerPath) {
            Remove-Item $InstallerPath -Force
        }
    }
}

# Main installation dispatcher
function Install-Application {
    param([string]$AppName)
    
    $Result = switch ($AppName.ToLower()) {
        "chrome" { Install-GoogleChrome }
        "vscode" { Install-VSCode }
        "docker-desktop" { Install-DockerDesktop }
        "teams" { Install-MicrosoftTeams }
        default {
            Write-Log "Unknown application: $AppName" "ERROR"
            return @{ Success = $false; Error = "Unknown application" }
        }
    }
    
    # Create deployment record
    if ($Result.Success) {
        $DeploymentRecord = @{
            app = $AppName
            app_name = $AppName
            version = $Result.Version
            status = "installed"
            deployment_time = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
            target_device = $env:COMPUTERNAME
            platform = "windows"
            deployment_method = "msi/exe"
            installed_by = "opendirectory-windows-agent"
            requires_restart = $Result.RequiresRestart -eq $true
        }
        
        $RecordPath = "$DeploymentPath\$AppName-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
        $DeploymentRecord | ConvertTo-Json | Out-File -FilePath $RecordPath -Encoding UTF8
        
        # Notify OpenDirectory server
        try {
            $NotificationData = @{
                device_id = $env:COMPUTERNAME
                app = $AppName
                status = "success"
                version = $Result.Version
                platform = "windows"
            }
            
            $JsonData = $NotificationData | ConvertTo-Json
            Invoke-RestMethod -Uri "http://$OpenDirectoryServer/api/deployments/status" -Method Post -Body $JsonData -ContentType "application/json"
            Write-Log "Deployment notification sent to OpenDirectory server" "SUCCESS"
        }
        catch {
            Write-Log "Failed to notify OpenDirectory server: $($_.Exception.Message)" "WARNING"
        }
    }
    
    return $Result
}

# Show system status
function Show-SystemStatus {
    Write-Log "=== OpenDirectory Windows Deployment Agent ==="
    $SystemInfo = Get-SystemInfo
    
    Write-Log "Device: $($SystemInfo.Hostname)"
    Write-Log "OS: $($SystemInfo.OS) ($($SystemInfo.Architecture))"
    Write-Log "Domain: $($SystemInfo.Domain)"
    Write-Log "Memory: $($SystemInfo.TotalMemory) GB"
    Write-Log "Log Path: $LogPath"
    Write-Log "Deployment Path: $DeploymentPath"
    
    Write-Log "=== Installed Applications ==="
    
    # Check for common applications
    $Apps = @{
        "Google Chrome" = "${env:ProgramFiles}\Google\Chrome\Application\chrome.exe"
        "VS Code" = "${env:ProgramFiles}\Microsoft VS Code\Code.exe"
        "Docker Desktop" = "${env:ProgramFiles}\Docker\Docker\Docker Desktop.exe"
        "Microsoft Teams" = "${env:APPDATA}\Microsoft\Teams\current\Teams.exe"
    }
    
    foreach ($AppName in $Apps.Keys) {
        $AppPath = $Apps[$AppName]
        if (Test-Path $AppPath) {
            try {
                $Version = (Get-ItemProperty $AppPath).VersionInfo.FileVersion
                Write-Log "✅ $AppName: $Version"
            }
            catch {
                Write-Log "✅ $AppName: Installed"
            }
        }
        else {
            Write-Log "❌ $AppName: Not installed"
        }
    }
    
    # Show deployment history
    Write-Log "=== Deployment History ==="
    $DeploymentFiles = Get-ChildItem -Path $DeploymentPath -Filter "*.json" -ErrorAction SilentlyContinue
    if ($DeploymentFiles) {
        $DeploymentFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 5 | ForEach-Object {
            Write-Log "📄 $($_.Name)"
        }
    } else {
        Write-Log "No deployment records found"
    }
}

# Main execution
try {
    Write-Log "OpenDirectory Windows Deployment Agent started"
    Write-Log "Application: $Application, Version: $Version"
    
    if ($Application -eq "status") {
        Show-SystemStatus
    }
    else {
        $Result = Install-Application -AppName $Application
        
        if ($Result.Success) {
            Write-Log "✅ Deployment completed successfully!" "SUCCESS"
            if ($Result.RequiresRestart) {
                Write-Log "⚠️  System restart recommended" "WARNING"
            }
            exit 0
        }
        else {
            Write-Log "❌ Deployment failed: $($Result.Error)" "ERROR"
            exit 1
        }
    }
}
catch {
    Write-Log "Fatal error: $($_.Exception.Message)" "ERROR"
    exit 1
}