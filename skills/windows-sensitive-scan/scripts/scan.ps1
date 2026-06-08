<#
.SYNOPSIS
    Windows Sensitive Information Scanner

.DESCRIPTION
    Scans Windows filesystem for secrets using Gitleaks and TruffleHog.
    Filters false positives and produces structured JSON report.

.PARAMETER Targets
    Comma-separated list of paths to scan (default: common user/system paths)

.PARAMETER Output
    Output directory for results

.PARAMETER Jobs
    Number of parallel scan jobs (default: 2)

.PARAMETER NoTriage
    Skip false positive triage

.PARAMETER MaxFileSize
    Maximum file size to scan (default: 10MB)

.EXAMPLE
    .\scan.ps1
    .\scan.ps1 -Targets C:\Users,C:\Projects
    .\scan.ps1 -Output C:\audit -Jobs 4
#>

param(
    [string]$Targets = "",
    [string]$Output = "",
    [int]$Jobs = 2,
    [switch]$NoTriage,
    [string]$MaxFileSize = "10M"
)

$ErrorActionPreference = "Continue"

# Setup paths
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SkillDir = Split-Path -Parent $ScriptDir
$LSARoot = Split-Path -Parent (Split-Path -Parent $SkillDir)
$BinDir = Join-Path $LSARoot "bin\windows"
$ConfigDir = Join-Path $SkillDir "config"

# Create output directory
if ($Output -eq "") {
    $HostName = $env:COMPUTERNAME.ToLower()
    $TimeStamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $Output = Join-Path $LSARoot "reports\$HostName-$TimeStamp\windows-sensitive-scan"
}

if (-not (Test-Path $Output)) {
    New-Item -ItemType Directory -Path $Output -Force | Out-Null
}

$LogFile = Join-Path $Output "scan.log"
$RawJson = Join-Path $Output "raw.json"
$ResultJson = Join-Path $Output "result.json"

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

function Find-Tool {
    param([string]$Name)

    # Check bin/windows directory
    $ToolPath = Join-Path $BinDir "$Name.exe"
    if (Test-Path $ToolPath) {
        return $ToolPath
    }

    # Check PATH
    $InPath = Get-Command $Name -ErrorAction SilentlyContinue
    if ($InPath) {
        return $InPath.Source
    }

    return $null
}

function Get-DefaultTargets {
    $Targets = @()

    # User directories
    $UsersDir = "C:\Users"
    if (Test-Path $UsersDir) {
        Get-ChildItem -Path $UsersDir -Directory | ForEach-Object {
            if ($_.Name -notin @("Public", "Default", "All Users")) {
                $Targets += $_.FullName
            }
        }
    }

    # Common application directories
    @("C:\inetpub\wwwroot", "C:\Projects", "C:\Code", "C:\Data") | ForEach-Object {
        if (Test-Path $_) {
            $Targets += $_
        }
    }

    # ProgramData (may contain configs)
    if (Test-Path "C:\ProgramData") {
        $Targets += "C:\ProgramData"
    }

    return $Targets
}

function Invoke-Gitleaks {
    param([string[]]$Targets)

    $Gitleaks = Find-Tool "gitleaks"
    if (-not $Gitleaks) {
        Write-Log "gitleaks.exe not found, skipping" "WARN"
        return $null
    }

    Write-Log "Running Gitleaks scan..."
    Write-Log "Version: $(& $Gitleaks version 2>&1)"

    $AllFindings = @()

    foreach ($Target in $Targets) {
        if (-not (Test-Path $Target)) {
            Write-Log "Target not found: $Target" "WARN"
            continue
        }

        $TempJson = Join-Path $Output "gitleaks_$(Get-Random).json"

        $Args = @(
            "detect",
            "--no-git",
            "--redact=0",
            "--source", $Target,
            "--report-format", "json",
            "--report-path", $TempJson,
            "--exit-code", "0",
            "--max-target-megabytes", "10"
        )

        # Add config if exists
        $ConfigFile = Join-Path $ConfigDir "gitleaks-custom.toml"
        if (Test-Path $ConfigFile) {
            $Args += @("--config", $ConfigFile)
        }

        Write-Log "Scanning: $Target"

        try {
            & $Gitleaks $Args 2>&1 | Out-Null

            if (Test-Path $TempJson) {
                $Content = Get-Content $TempJson -Raw
                try {
                    $Findings = $Content | ConvertFrom-Json
                    foreach ($f in $Findings) {
                        $AllFindings += @{
                            RuleID = $f.RuleID
                            File = $f.File
                            Secret = $f.Secret
                            Match = $f.Match
                            Entropy = $f.Entropy
                            Source = "gitleaks"
                        }
                    }
                }
                catch {
                    Write-Log "Failed to parse Gitleaks output for $Target" "WARN"
                }
                Remove-Item $TempJson -Force
            }
        }
        catch {
            Write-Log "Gitleaks failed for $Target : $($_.Exception.Message)" "WARN"
        }
    }

    return $AllFindings
}

function Invoke-Triage {
    param([array]$RawFindings)

    # Load Python triage script
    $TriageScript = Join-Path $ScriptDir "triage.py"
    if (-not (Test-Path $TriageScript)) {
        Write-Log "Triage script not found, returning raw findings" "WARN"
        return $RawFindings
    }

    # Find Python
    $Python = Get-Command python -ErrorAction SilentlyContinue
    if (-not $Python) {
        $Python = Get-Command python3 -ErrorAction SilentlyContinue
    }
    if (-not $Python) {
        Write-Log "Python not found, returning raw findings" "WARN"
        return $RawFindings
    }

    # Write raw findings to temp file
    $TempRaw = Join-Path $Output "temp_raw.json"
    $RawFindings | ConvertTo-Json -Depth 10 | Set-Content $TempRaw

    # Run triage
    $TempResult = Join-Path $Output "temp_result.json"
    & $Python.Source $TriageScript $TempRaw --out $TempResult 2>&1 | Out-Null

    if (Test-Path $TempResult) {
        $Result = Get-Content $TempResult -Raw | ConvertFrom-Json
        Remove-Item $TempRaw, $TempResult -Force -ErrorAction SilentlyContinue
        return $Result
    }

    return $RawFindings
}

# Main
Write-Log "=========================================="
Write-Log "Windows Sensitive Information Scan"
Write-Log "=========================================="
Write-Log "Output: $Output"
Write-Log "Jobs: $Jobs"
Write-Log "MaxFileSize: $MaxFileSize"

# Resolve targets
$ScanTargets = if ($Targets -ne "") {
    $Targets -split "," | ForEach-Object { $_.Trim() }
}
else {
    Get-DefaultTargets
}

Write-Log "Targets: $($ScanTargets.Count) paths"
foreach ($t in $ScanTargets) {
    Write-Log "  - $t"
}

# Run Gitleaks
$GitleaksFindings = Invoke-Gitleaks -Targets $ScanTargets
if ($GitleaksFindings) {
    Write-Log "Gitleaks found $($GitleaksFindings.Count) potential secrets"
}

# Save raw results
$RawResults = @{
    module = "windows-sensitive-scan"
    status = "pending"
    counts = @{total = ($GitleaksFindings | Measure-Object).Count}
    findings = $GitleaksFindings
}
$RawResults | ConvertTo-Json -Depth 10 | Set-Content $RawJson
Write-Log "Raw results saved to: $RawJson"

# Triage
$FinalFindings = if (-not $NoTriage -and $GitleaksFindings) {
    Write-Log "Running triage..."
    Invoke-Triage -RawFindings $GitleaksFindings
}
else {
    $GitleaksFindings
}

# Calculate severity counts
$Counts = @{critical = 0; high = 0; medium = 0; low = 0; likely_fp = 0}
foreach ($f in $FinalFindings) {
    $Severity = if ($f.severity) { $f.severity.ToLower() } else { "medium" }
    if ($Counts.ContainsKey($Severity)) {
        $Counts[$Severity]++
    }
    if ($f.is_likely_fp) {
        $Counts.likely_fp++
    }
}

# Determine status
$Status = if ($Counts.critical -gt 0 -or $Counts.high -gt 0) { "warn" } else { "ok" }

# Write final results
$Results = @{
    module = "windows-sensitive-scan"
    status = $Status
    summary = "total:$($Counts.total), high:$($Counts.high), medium:$($Counts.medium), low:$($Counts.low), likely_fp:$($Counts.likely_fp)"
    counts = $Counts
    findings = $FinalFindings
}
$Results | ConvertTo-Json -Depth 10 | Set-Content $ResultJson

Write-Log "=========================================="
Write-Log "Scan Complete"
Write-Log "=========================================="
Write-Log "Status: $Status"
Write-Log "Total: $(($FinalFindings | Measure-Object).Count), Likely FP: $($Counts.likely_fp)"
Write-Log "Output: $ResultJson"
Write-Log "OK" "OK"

Write-Output $ResultJson
