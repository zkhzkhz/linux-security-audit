<#
.SYNOPSIS
    Windows Egress Control Audit

.DESCRIPTION
    Audits Windows firewall and network configuration for egress control issues.

.PARAMETER Output
    Output directory for results

.EXAMPLE
    .\audit.ps1
    .\audit.ps1 -Output C:\audit
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
    $Output = Join-Path $LSARoot "reports\$HostName-$TimeStamp\windows-egress-control"
}

if (-not (Test-Path $Output)) {
    New-Item -ItemType Directory -Path $Output -Force | Out-Null
}

$LogFile = Join-Path $Output "audit.log"
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

function Get-FirewallFindings {
    $Findings = @()

    Write-Log "Checking Windows Firewall..."

    # Check firewall status
    try {
        $FirewallProfiles = Get-NetFirewallProfile

        foreach ($Profile in $FirewallProfiles) {
            if ($Profile.Enabled -eq $false) {
                $Findings += @{
                    severity = "high"
                    title = "firewall-disabled"
                    where = "firewall:$($Profile.Name)"
                    note = "Windows Firewall is disabled for $($Profile.Name) profile"
                }
            }

            # Check default outbound action
            if ($Profile.DefaultOutboundAction -eq "Allow") {
                $Findings += @{
                    severity = "medium"
                    title = "unrestricted-egress"
                    where = "firewall:$($Profile.Name)"
                    note = "Default outbound action is Allow for $($Profile.Name) profile"
                }
            }
        }
    }
    catch {
        Write-Log "Failed to check firewall: $($_.Exception.Message)" "WARN"
    }

    # Check for allow-all outbound rules
    Write-Log "Checking outbound rules..."
    try {
        $OutboundRules = Get-NetFirewallRule -Direction Outbound -Enabled True -Action Allow -ErrorAction SilentlyContinue
        $AnyRules = $OutboundRules | Where-Object {
            $_.DisplayName -like "*Any*" -or
            $_.DisplayName -like "*All*" -or
            $_.DisplayName -like "*Default*"
        }

        if ($AnyRules) {
            $Findings += @{
                severity = "medium"
                title = "permissive-outbound-rules"
                where = "firewall:outbound"
                note = "Permissive outbound rules found: $($AnyRules.Count) rules"
            }
        }
    }
    catch {}

    return $Findings
}

function Get-ProxyFindings {
    $Findings = @()

    Write-Log "Checking proxy configuration..."

    # Check system proxy
    try {
        $Proxy = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue

        if ($Proxy -and $Proxy.ProxyEnable -eq 1) {
            $Findings += @{
                severity = "info"
                title = "proxy-configured"
                where = "registry:Internet Settings"
                note = "System proxy configured: $($Proxy.ProxyServer)"
            }
        }
        elseif ($Proxy -and $Proxy.ProxyEnable -eq 0) {
            $Findings += @{
                severity = "low"
                title = "no-proxy"
                where = "registry:Internet Settings"
                note = "No system proxy configured - direct internet access"
            }
        }
    }
    catch {}

    # Check WinHTTP proxy
    try {
        $WinHttpProxy = netsh winhttp show proxy 2>&1
        if ($WinHttpProxy -match "Proxy Server\(s\)\s+:\s+(.+)") {
            $Findings += @{
                severity = "info"
                title = "winhttp-proxy"
                where = "winhttp"
                note = "WinHTTP proxy: $($Matches[1])"
            }
        }
    }
    catch {}

    return $Findings
}

function Get-DNSFindings {
    $Findings = @()

    Write-Log "Checking DNS configuration..."

    try {
        $Adapters = Get-DnsClientServerAddress -AddressFamily IPv4

        foreach ($Adapter in $Adapters) {
            $Server = $Adapter.ServerAddresses
            if ($Server) {
                # Check for public DNS servers
                $PublicDNS = @("8.8.8.8", "8.8.4.4", "1.1.1.1", "208.67.222.222", "208.67.220.220")
                $UsingPublic = $Server | Where-Object { $_ -in $PublicDNS }

                if ($UsingPublic) {
                    $Findings += @{
                        severity = "low"
                        title = "public-dns"
                        where = "dns:$($Adapter.InterfaceAlias)"
                        note = "Using public DNS servers: $($UsingPublic -join ', ')"
                    }
                }
            }
        }
    }
    catch {
        Write-Log "Failed to check DNS: $($_.Exception.Message)" "WARN"
    }

    return $Findings
}

function Get-NetworkIsolationFindings {
    $Findings = @()

    Write-Log "Checking network isolation..."

    # Check network categories
    try {
        $Networks = Get-NetConnectionProfile
        foreach ($Net in $Networks) {
            if ($Net.NetworkCategory -eq "Public") {
                $Findings += @{
                    severity = "info"
                    title = "public-network"
                    where = "network:$($Net.Name)"
                    note = "Network is set to Public category"
                }
            }
        }
    }
    catch {}

    return $Findings
}

# Main
Write-Log "=========================================="
Write-Log "Windows Egress Control Audit"
Write-Log "=========================================="
Write-Log "Output: $Output"

$AllFindings = @()

$AllFindings += Get-FirewallFindings
$AllFindings += Get-ProxyFindings
$AllFindings += Get-DNSFindings
$AllFindings += Get-NetworkIsolationFindings

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
    module = "windows-egress-control"
    status = $Status
    summary = "high:$($Counts.high), medium:$($Counts.medium), low:$($Counts.low)"
    counts = $Counts
    findings = $AllFindings
}

$Result | ConvertTo-Json -Depth 10 | Set-Content $ResultFile

Write-Log "=========================================="
Write-Log "Audit Complete"
Write-Log "=========================================="
Write-Log "Status: $Status"
Write-Log "High: $($Counts.high), Medium: $($Counts.medium), Low: $($Counts.low)"
Write-Log "Output: $ResultFile"
Write-Log "OK" "OK"

Write-Output $ResultFile
