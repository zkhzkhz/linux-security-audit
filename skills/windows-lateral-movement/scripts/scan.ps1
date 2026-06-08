<#
.SYNOPSIS
    Windows Lateral Movement Scanner

.DESCRIPTION
    Scans for lateral movement risks including network exposure, credential caching,
    remote access configurations, and session information.

.PARAMETER Output
    Output directory for results

.EXAMPLE
    .\scan.ps1
    .\scan.ps1 -Output C:\audit
#>

param(
    [string]$Output = ""
)

$ErrorActionPreference = "Continue"

# Setup paths
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SkillDir = Split-Path -Parent $ScriptDir
$LSARoot = Split-Path -Parent (Split-Path -Parent $SkillDir)

# Create output directory
if ($Output -eq "") {
    $HostName = $env:COMPUTERNAME.ToLower()
    $TimeStamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $Output = Join-Path $LSARoot "reports\$HostName-$TimeStamp\windows-lateral-movement"
}

if (-not (Test-Path $Output)) {
    New-Item -ItemType Directory -Path $Output -Force | Out-Null
}

$LogFile = Join-Path $Output "scan.log"
$ResultFile = Join-Path $Output "result.json"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $TimeStamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
    $Color = switch ($Level) {
        "INFO"  { "Cyan" }
        "WARN"  { "Yellow" }
        "ERROR" { "Red" }
        "OK"    { "Green" }
        default { "White" }
    }
    $Line = "[$Level $TimeStamp] $Message"
    Write-Host $Line -ForegroundColor $Color
    Add-Content -Path $LogFile -Value $Line
}

function Get-NetworkFindings {
    $Findings = @()

    # Check open ports
    Write-Log "Checking network ports..."
    try {
        $Connections = netstat -ano | Select-String "LISTENING"
        $Ports = @()
        foreach ($Conn in $Connections) {
            if ($Conn -match ":(\d+)\s+.*LISTENING") {
                $Port = $Matches[1]
                if ($Port -in @("3389", "5985", "5986", "22", "445", "139", "135")) {
                    $Ports += $Port
                }
            }
        }
        if ($Ports.Count -gt 0) {
            $Findings += @{
                severity = "medium"
                title = "sensitive-ports-open"
                where = "network"
                note = "Sensitive ports listening: $($Ports -join ', ')"
            }
        }
    }
    catch {
        Write-Log "Failed to check network ports: $($_.Exception.Message)" "WARN"
    }

    # Check SMB
    Write-Log "Checking SMB configuration..."
    try {
        $SmbServer = Get-Service -Name LanmanServer -ErrorAction SilentlyContinue
        if ($SmbServer -and $SmbServer.Status -eq "Running") {
            $Findings += @{
                severity = "medium"
                title = "smb-enabled"
                where = "service:LanmanServer"
                note = "SMB server is running"
            }
        }
    }
    catch {}

    # Check network shares
    Write-Log "Checking network shares..."
    try {
        $Shares = Get-SmbShare | Where-Object { $_.Name -ne "IPC$" -and $_.Name -ne "ADMIN$" }
        if ($Shares) {
            $Findings += @{
                severity = "low"
                title = "network-shares"
                where = "smb"
                note = "Network shares exposed: $($Shares.Name -join ', ')"
            }
        }
    }
    catch {}

    return $Findings
}

function Get-CredentialFindings {
    $Findings = @()

    # Check cached credentials
    Write-Log "Checking cached credentials..."
    try {
        $CachedLogons = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name CachedLogonsCount -ErrorAction SilentlyContinue
        if ($CachedLogons -and $CachedLogons.CachedLogonsCount -gt 0) {
            $Findings += @{
                severity = "low"
                title = "cached-credentials"
                where = "registry:Winlogon"
                note = "Cached logons enabled: $($CachedLogons.CachedLogonsCount)"
            }
        }
    }
    catch {}

    # Check saved RDP credentials
    Write-Log "Checking saved RDP credentials..."
    try {
        $RdpCreds = Get-ChildItem -Path "$env:USERPROFILE\AppData\Local\Microsoft\Credentials" -ErrorAction SilentlyContinue
        if ($RdpCreds) {
            $Findings += @{
                severity = "medium"
                title = "saved-rdp-credentials"
                where = "$env:USERPROFILE\AppData\Local\Microsoft\Credentials"
                note = "Saved credentials found: $($RdpCreds.Count) files"
            }
        }
    }
    catch {}

    # Check for saved Windows credentials
    Write-Log "Checking saved Windows credentials..."
    try {
        $Cmdkey = cmdkey /list 2>&1
        if ($Cmdkey -match "Domain:target=") {
            $Count = ($Cmdkey | Select-String "Domain:target=").Count
            $Findings += @{
                severity = "medium"
                title = "saved-windows-credentials"
                where = "cmdkey"
                note = "Saved Windows credentials: $Count entries"
            }
        }
    }
    catch {}

    return $Findings
}

function Get-RemoteAccessFindings {
    $Findings = @()

    # Check RDP
    Write-Log "Checking RDP configuration..."
    try {
        $Rdp = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -ErrorAction SilentlyContinue
        if ($Rdp -and $Rdp.fDenyTSConnections -eq 0) {
            $Findings += @{
                severity = "medium"
                title = "rdp-enabled"
                where = "registry:Terminal Server"
                note = "RDP is enabled"
            }

            # Check NLA
            $Nla = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name UserAuthentication -ErrorAction SilentlyContinue
            if ($Nla -and $Nla.UserAuthentication -eq 0) {
                $Findings += @{
                    severity = "high"
                    title = "rdp-nla-disabled"
                    where = "registry:RDP-Tcp"
                    note = "RDP Network Level Authentication is disabled"
                }
            }
        }
    }
    catch {}

    # Check WinRM
    Write-Log "Checking WinRM configuration..."
    try {
        $Winrm = Get-Service -Name WinRM -ErrorAction SilentlyContinue
        if ($Winrm -and $Winrm.Status -eq "Running") {
            $Findings += @{
                severity = "medium"
                title = "winrm-enabled"
                where = "service:WinRM"
                note = "WinRM service is running"
            }
        }
    }
    catch {}

    # Check SSH
    Write-Log "Checking SSH service..."
    try {
        $Sshd = Get-Service -Name sshd -ErrorAction SilentlyContinue
        if ($Sshd -and $Sshd.Status -eq "Running") {
            $Findings += @{
                severity = "medium"
                title = "ssh-enabled"
                where = "service:sshd"
                note = "SSH service is running"
            }
        }
    }
    catch {}

    return $Findings
}

function Get-SessionFindings {
    $Findings = @()

    # Check active sessions
    Write-Log "Checking active sessions..."
    try {
        $Sessions = query session 2>$null
        if ($Sessions) {
            $ActiveUsers = ($Sessions | Select-String "Active").Count
            if ($ActiveUsers -gt 0) {
                $Findings += @{
                    severity = "info"
                    title = "active-sessions"
                    where = "sessions"
                    note = "Active user sessions: $ActiveUsers"
                }
            }
        }
    }
    catch {}

    # Check logged on users
    Write-Log "Checking logged on users..."
    try {
        $Users = query user 2>$null
        if ($Users) {
            $Findings += @{
                severity = "info"
                title = "logged-on-users"
                where = "users"
                note = "Users currently logged on"
            }
        }
    }
    catch {}

    return $Findings
}

# Main
Write-Log "=========================================="
Write-Log "Windows Lateral Movement Scan"
Write-Log "=========================================="
Write-Log "Output: $Output"

$AllFindings = @()

$AllFindings += Get-NetworkFindings
$AllFindings += Get-CredentialFindings
$AllFindings += Get-RemoteAccessFindings
$AllFindings += Get-SessionFindings

# Count by severity
$Counts = @{critical = 0; high = 0; medium = 0; low = 0; info = 0}
foreach ($f in $AllFindings) {
    $Sev = $f.severity.ToLower()
    if ($Counts.ContainsKey($Sev)) {
        $Counts[$Sev]++
    }
}

$Status = if ($Counts.high -gt 0) { "warn" } elseif ($Counts.medium -gt 0) { "warn" } else { "ok" }

$Result = @{
    module = "windows-lateral-movement"
    status = $Status
    summary = "high:$($Counts.high), medium:$($Counts.medium), low:$($Counts.low)"
    counts = $Counts
    findings = $AllFindings
}

$Result | ConvertTo-Json -Depth 10 | Set-Content $ResultFile

Write-Log "=========================================="
Write-Log "Scan Complete"
Write-Log "=========================================="
Write-Log "Status: $Status"
Write-Log "High: $($Counts.high), Medium: $($Counts.medium), Low: $($Counts.low)"
Write-Log "Output: $ResultFile"
Write-Log "OK" "OK"

Write-Output $ResultFile
