<#
.SYNOPSIS
    Windows Privilege Escalation Audit - Main Entry Point

.DESCRIPTION
    Runs WinPEAS, Seatbelt, SharpUp, and Watson to audit Windows privilege escalation vectors.
    Aggregates results into a structured JSON report.

.PARAMETER Output
    Output directory for results

.PARAMETER Tools
    Comma-separated list of tools to run (default: all)
    Options: winpeas, seatbelt, sharpup, watson

.PARAMETER Timeout
    Timeout per tool in seconds (default: 600)

.PARAMETER NoParse
    Skip parsing and produce raw output only

.EXAMPLE
    .\run.ps1
    .\run.ps1 -Tools winpeas,watson
    .\run.ps1 -Output C:\audit -Timeout 300
#>

param(
    [string]$Output = "",
    [string]$Tools = "all",
    [int]$Timeout = 600,
    [switch]$NoParse
)

$ErrorActionPreference = "Continue"

# Setup paths
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SkillDir = Split-Path -Parent $ScriptDir
$LSARoot = Split-Path -Parent (Split-Path -Parent $SkillDir)
$BinDir = Join-Path $LSARoot "bin\windows"

# Create output directory
if ($Output -eq "") {
    $HostName = $env:COMPUTERNAME.ToLower()
    $TimeStamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $Output = Join-Path $LSARoot "reports\$HostName-$TimeStamp\windows-privesc-check"
}

if (-not (Test-Path $Output)) {
    New-Item -ItemType Directory -Path $Output -Force | Out-Null
}

$LogFile = Join-Path $Output "host.log"
$JsonFile = Join-Path $Output "host.json"

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

function Run-WinPEAS {
    $ToolPath = Find-Tool "winpeas"
    if (-not $ToolPath) {
        Write-Log "winpeas.exe not found, skipping" "WARN"
        return $null
    }

    Write-Log "Running WinPEAS..."
    $OutFile = Join-Path $Output "winpeas_raw.txt"

    try {
        $Process = Start-Process -FilePath $ToolPath -ArgumentList "cmd" `
            -RedirectStandardOutput $OutFile `
            -RedirectStandardError (Join-Path $Output "winpeas_stderr.txt") `
            -NoNewWindow -PassThru

        if (-not $Process.WaitForExit($Timeout * 1000)) {
            $Process.Kill()
            Write-Log "WinPEAS timed out after ${Timeout}s" "WARN"
        }

        Write-Log "WinPEAS completed"
        return $OutFile
    }
    catch {
        Write-Log "WinPEAS failed: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Run-Seatbelt {
    $ToolPath = Find-Tool "seatbelt"
    if (-not $ToolPath) {
        Write-Log "seatbelt.exe not found, skipping" "WARN"
        return $null
    }

    Write-Log "Running Seatbelt..."
    $OutFile = Join-Path $Output "seatbelt_raw.txt"

    try {
        $Process = Start-Process -FilePath $ToolPath -ArgumentList "-group=all" `
            -RedirectStandardOutput $OutFile `
            -RedirectStandardError (Join-Path $Output "seatbelt_stderr.txt") `
            -NoNewWindow -PassThru

        if (-not $Process.WaitForExit($Timeout * 1000)) {
            $Process.Kill()
            Write-Log "Seatbelt timed out after ${Timeout}s" "WARN"
        }

        Write-Log "Seatbelt completed"
        return $OutFile
    }
    catch {
        Write-Log "Seatbelt failed: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Run-SharpUp {
    $ToolPath = Find-Tool "sharpup"
    if (-not $ToolPath) {
        Write-Log "sharpup.exe not found, skipping" "WARN"
        return $null
    }

    Write-Log "Running SharpUp..."
    $OutFile = Join-Path $Output "sharpup_raw.txt"

    try {
        $Process = Start-Process -FilePath $ToolPath -ArgumentList "audit" `
            -RedirectStandardOutput $OutFile `
            -RedirectStandardError (Join-Path $Output "sharpup_stderr.txt") `
            -NoNewWindow -PassThru

        if (-not $Process.WaitForExit($Timeout * 1000)) {
            $Process.Kill()
            Write-Log "SharpUp timed out after ${Timeout}s" "WARN"
        }

        Write-Log "SharpUp completed"
        return $OutFile
    }
    catch {
        Write-Log "SharpUp failed: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Run-Watson {
    $ToolPath = Find-Tool "watson"
    if (-not $ToolPath) {
        Write-Log "watson.exe not found, skipping" "WARN"
        return $null
    }

    Write-Log "Running Watson (kernel vulnerability scanner)..."
    $OutFile = Join-Path $Output "watson_raw.txt"

    try {
        $Process = Start-Process -FilePath $ToolPath `
            -RedirectStandardOutput $OutFile `
            -RedirectStandardError (Join-Path $Output "watson_stderr.txt") `
            -NoNewWindow -PassThru

        if (-not $Process.WaitForExit($Timeout * 1000)) {
            $Process.Kill()
            Write-Log "Watson timed out after ${Timeout}s" "WARN"
        }

        Write-Log "Watson completed"
        return $OutFile
    }
    catch {
        Write-Log "Watson failed: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Invoke-Parser {
    param([string]$Parser, [string]$InputFile)

    $PythonScript = Join-Path $ScriptDir "$Parser.py"
    if (-not (Test-Path $PythonScript)) {
        Write-Log "Parser not found: $PythonScript" "WARN"
        return $null
    }

    # Find Python
    $Python = Get-Command python -ErrorAction SilentlyContinue
    if (-not $Python) {
        $Python = Get-Command python3 -ErrorAction SilentlyContinue
    }
    if (-not $Python) {
        Write-Log "Python not found, skipping parsing" "WARN"
        return $null
    }

    $TempJson = Join-Path $Output "temp_$Parser.json"
    & $Python.Source $PythonScript $InputFile --out $TempJson 2>$null

    if (Test-Path $TempJson) {
        return $TempJson
    }
    return $null
}

# Main
Write-Log "=========================================="
Write-Log "Windows Privilege Escalation Audit"
Write-Log "=========================================="
Write-Log "Output: $Output"
Write-Log "Tools: $Tools"
Write-Log "Timeout: ${Timeout}s"

# Determine which tools to run
$ToolsToRun = if ($Tools -eq "all") {
    @("winpeas", "seatbelt", "sharpup", "watson")
}
else {
    $Tools -split "," | ForEach-Object { $_.Trim().ToLower() }
}

$AllFindings = @()
$Counts = @{critical = 0; high = 0; medium = 0; low = 0; info = 0}

foreach ($Tool in $ToolsToRun) {
    $RawFile = $null

    switch ($Tool) {
        "winpeas"   { $RawFile = Run-WinPEAS }
        "seatbelt"  { $RawFile = Run-Seatbelt }
        "sharpup"   { $RawFile = Run-SharpUp }
        "watson"    { $RawFile = Run-Watson }
        default     { Write-Log "Unknown tool: $Tool" "WARN" }
    }

    # Parse results
    if ($RawFile -and (Test-Path $RawFile) -and -not $NoParse) {
        Write-Log "Parsing $Tool results..."
        $ParsedJson = Invoke-Parser -Parser "parse_$Tool" -InputFile $RawFile

        if ($ParsedJson -and (Test-Path $ParsedJson)) {
            try {
                $ParsedData = Get-Content $ParsedJson -Raw | ConvertFrom-Json
                if ($ParsedData.findings) {
                    foreach ($f in $ParsedData.findings) {
                        $AllFindings += $f
                        $Severity = $f.severity.ToLower()
                        if ($Counts.ContainsKey($Severity)) {
                            $Counts[$Severity]++
                        }
                    }
                }
                Remove-Item $ParsedJson -Force
            }
            catch {
                Write-Log "Failed to parse $Tool JSON: $($_.Exception.Message)" "WARN"
            }
        }
    }
}

# Determine status
$Status = if ($Counts.critical -gt 0) { "critical" }
          elseif ($Counts.high -gt 0) { "warn" }
          elseif ($Counts.medium -gt 0) { "warn" }
          else { "ok" }

# Write final JSON
$Result = @{
    module = "windows-privesc-check"
    status = $Status
    summary = "critical:$($Counts.critical), high:$($Counts.high), medium:$($Counts.medium), low:$($Counts.low)"
    counts = $Counts
    findings = $AllFindings
}

$Result | ConvertTo-Json -Depth 10 | Set-Content $JsonFile

Write-Log "=========================================="
Write-Log "Audit Complete"
Write-Log "=========================================="
Write-Log "Status: $Status"
Write-Log "Critical: $($Counts.critical), High: $($Counts.high), Medium: $($Counts.medium), Low: $($Counts.low)"
Write-Log "Output: $JsonFile"
Write-Log "OK" "OK"

# Output the JSON file path
Write-Output $JsonFile
