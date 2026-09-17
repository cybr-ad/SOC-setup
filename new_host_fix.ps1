<#
.SYNOPSIS
    SOC Lab - Win 11 Host Side Splunk Enterprise Setup.

.DESCRIPTION
    Runs on the Win 11 host where Splunk Enterprise is installed.
    - Verifies Splunk Enterprise service is running
    - Enables receiving on port 9997 (idempotent)
    - Opens Windows Firewall for 9997 and 8000
    - Verifies the listener is bound
    - Confirms Splunk Web is reachable
    - Tests TCP from the host to itself
    - Shows live connections from VMs
    - Prints the exact SPL queries to verify logs

    Idempotent. Safe to re-run.
    Does NOT touch the VMs. Does NOT install anything.

.PARAMETER SplunkAdminUser
    Splunk admin username. Default socadmin.
.PARAMETER SplunkAdminPass
    Splunk admin password. Default P@ssw0rd2026!.
.PARAMETER SplunkPort
    Receiving port. Default 9997.
.PARAMETER WebPort
    Splunk Web port. Default 8000.
.PARAMETER VmSubnet
    VMnet8 subnet prefix. Default 192.168.10.
.PARAMETER NoPrompt
    Do not pause at the end (for non-interactive/CI use).
#>

[CmdletBinding()]
param(
    [string]$SplunkAdminUser = "socadmin",
    [string]$SplunkAdminPass = "P@ssw0rd2026!",
    [int]   $SplunkPort      = 9997,
    [int]   $WebPort         = 8000,
    [string]$VmSubnet        = "192.168.10",
    [switch]$NoPrompt
)

$ErrorActionPreference = "Continue"
$script:Failures = @()
$script:Warnings = @()
$script:LogFile  = $null
$script:Transcript = $null

# ---------------- Helpers ----------------
function Say {
    param([string]$Msg, [string]$Level = "INFO")
    $ts = Get-Date -Format "HH:mm:ss"
    $line = "[$ts][$Level] $Msg"
    switch ($Level) {
        "ERROR" { Write-Host $line -ForegroundColor Red;    $script:Failures += $Msg }
        "WARN"  { Write-Host $line -ForegroundColor Yellow; $script:Warnings += $Msg }
        "OK"    { Write-Host $line -ForegroundColor Green }
        "STEP"  { Write-Host ""
                  Write-Host ("=" * 72) -ForegroundColor Cyan
                  Write-Host "  $Msg" -ForegroundColor Cyan
                  Write-Host ("=" * 72) -ForegroundColor Cyan }
        default { Write-Host $line }
    }
    if ($script:LogFile) {
        try { Add-Content -Path $script:LogFile -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue } catch { }
    }
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Find-SplunkHome {
    $candidates = @(
        "C:\Program Files\Splunk",
        "D:\Program Files\Splunk",
        "E:\Program Files\Splunk"
    )
    foreach ($c in $candidates) {
        if (Test-Path (Join-Path $c "bin\splunk.exe")) { return $c }
    }
    foreach ($rk in @("HKLM:\SOFTWARE\Splunk","HKLM:\SOFTWARE\WOW6432Node\Splunk")) {
        try {
            $reg = Get-ItemProperty -Path $rk -ErrorAction SilentlyContinue
            if ($reg -and $reg.InstallPath) {
                if (Test-Path (Join-Path $reg.InstallPath "bin\splunk.exe")) { return $reg.InstallPath }
            }
        } catch { }
    }
    return $null
}

function Get-SplunkService {
    return Get-Service -Name "Splunkd" -ErrorAction SilentlyContinue
}

function Invoke-SplunkCli {
    param(
        [string[]]$CliArgs,
        [int]$TimeoutSec = 60
    )
    # Always inject -auth right after the subcommand
    $auth = "${SplunkAdminUser}:${SplunkAdminPass}"
    $full = @()
    if ($CliArgs.Count -ge 1) {
        $full += $CliArgs[0]     # subcommand
        $full += "-auth", $auth
        if ($CliArgs.Count -gt 1) { $full += $CliArgs[1..($CliArgs.Count-1)] }
    }
    try {
        return & $script:SplunkExe @full 2>&1
    } catch {
        return @("ERROR: $($_.Exception.Message)")
    }
}

# ---------------- Bootstrap ----------------
$logDir = "C:\SOC-Lab\Logs"
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }

$script:LogFile    = Join-Path $logDir ("Win11SplunkHost-{0}.log" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
$script:Transcript = Join-Path $logDir ("Win11SplunkHost-transcript-{0}.txt" -f (Get-Date -Format "yyyyMMdd_HHmmss"))

try { Start-Transcript -Path $script:Transcript -Force -ErrorAction SilentlyContinue | Out-Null } catch { }

Write-Host ""
Write-Host "##############################################################" -ForegroundColor Magenta
Write-Host "#   SOC Lab - Win 11 Host Splunk Enterprise Setup           #" -ForegroundColor Magenta
Write-Host "##############################################################" -ForegroundColor Magenta
Write-Host ""
Say "Log: $script:LogFile"

# ---------------- PHASE 0 : Sanity ----------------
Say "Phase 0: Sanity" "STEP"

if (-not (Test-Admin)) {
    Say "Not running as Administrator. Reopen PowerShell as Admin." "ERROR"
    if (-not $NoPrompt) { Read-Host "Press Enter to exit" }
    try { Stop-Transcript | Out-Null } catch { }
    exit 1
}
Say "Administrator confirmed." "OK"

$splunkHome = Find-SplunkHome
if (-not $splunkHome) {
    Say "Splunk Enterprise not found. Looked in Program Files and registry." "ERROR"
    Write-Host ""
    Write-Host "Install Splunk Enterprise from https://www.splunk.com/en_us/download/splunk-enterprise.html" -ForegroundColor Yellow
    if (-not $NoPrompt) { Read-Host "Press Enter to exit" }
    try { Stop-Transcript | Out-Null } catch { }
    exit 1
}
Say "Splunk Enterprise found at: $splunkHome" "OK"

$script:SplunkExe = Join-Path $splunkHome "bin\splunk.exe"

# ---- VMnet8 IP detection ----
$vmnet8IP = $null
try {
    # Prefer VMnet8 by interface name
    $cand = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceAlias -match "VMnet8" } |
        Select-Object -First 1
    if ($cand) {
        $vmnet8IP = $cand.IPAddress
    } else {
        # Fallback: any IP in the VmSubnet
        $cand = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -like "$VmSubnet.*" -and $_.IPAddress -ne "127.0.0.1" } |
            Select-Object -First 1
        if ($cand) { $vmnet8IP = $cand.IPAddress }
    }
} catch { }

if ($vmnet8IP) {
    Say "VMnet8 adapter IP: $vmnet8IP" "OK"
} else {
    Say "Could not detect a $VmSubnet.x address on this host." "WARN"
}

# ---------------- PHASE 1 : Service ----------------
Say "Phase 1: Splunk Enterprise service" "STEP"

$svc = Get-SplunkService
if (-not $svc) {
    Say "Splunkd service not found." "ERROR"
    if (-not $NoPrompt) { Read-Host "Press Enter to exit" }
    try { Stop-Transcript | Out-Null } catch { }
    exit 1
}

if ($svc.Status -eq "Running") {
    Say "Splunkd is Running." "OK"
} else {
    Say "Splunkd is $($svc.Status). Starting..." "WARN"
    try {
        Start-Service Splunkd
        Start-Sleep 30
        $svc = Get-SplunkService
        Say "Splunkd status: $($svc.Status)" "OK"
    } catch {
        Say "Could not start Splunkd: $($_.Exception.Message)" "ERROR"
        if (-not $NoPrompt) { Read-Host "Press Enter to exit" }
        try { Stop-Transcript | Out-Null } catch { }
        exit 1
    }
}

# ---------------- PHASE 2 : Enable receiver ----------------
Say "Phase 2: Enable TCP receiver on port $SplunkPort" "STEP"

$localDir    = Join-Path $splunkHome "etc\system\local"
$inputsConf  = Join-Path $localDir "inputs.conf"
$receiverTag = "[splunktcp://$SplunkPort]"

$alreadyEnabled = $false
if (Test-Path $inputsConf) {
    $content = Get-Content $inputsConf -Raw -ErrorAction SilentlyContinue
    if ($content -and ($content -match [regex]::Escape($receiverTag))) {
        $alreadyEnabled = $true
    }
}

if ($alreadyEnabled) {
    Say "Receiver stanza already present in inputs.conf." "OK"
} else {
    Say "Enabling receiver via CLI..." "INFO"
    Invoke-SplunkCli -CliArgs @("enable","listen",$SplunkPort) | ForEach-Object { Say $_ "INFO" }

    Say "Restarting Splunkd to apply..." "INFO"
    Invoke-SplunkCli -CliArgs @("restart") | ForEach-Object { Say $_ "INFO" }
    Start-Sleep 30
}

# Safety net: ensure stanza in inputs.conf
if (-not (Test-Path $inputsConf)) {
    New-Item -ItemType Directory -Path $localDir -Force | Out-Null
    Set-Content -Path $inputsConf -Value "$receiverTag`r`nconnection_host = ip`r`n" -Encoding ASCII
    Say "Created inputs.conf with receiver stanza." "OK"
    Restart-Service Splunkd -Force -ErrorAction SilentlyContinue
    Start-Sleep 30
} elseif (-not ((Get-Content $inputsConf -Raw -ErrorAction SilentlyContinue) -match [regex]::Escape($receiverTag))) {
    Add-Content -Path $inputsConf -Value "`r`n$receiverTag`r`nconnection_host = ip`r`n" -Encoding ASCII
    Say "Appended receiver stanza to inputs.conf." "OK"
    Restart-Service Splunkd -Force -ErrorAction SilentlyContinue
    Start-Sleep 30
}

# Verify with CLI
$listenOut = Invoke-SplunkCli -CliArgs @("display","listen")
$foundListen = $false
foreach ($line in $listenOut) {
    if ($line -match "Receiving") { Say $line "OK"; $foundListen = $true }
}
if (-not $foundListen) { Say "CLI did not report a receiving port (may still be running)." "WARN" }

# ---------------- PHASE 3 : Firewall ----------------
Say "Phase 3: Windows Firewall" "STEP"

function Ensure-FirewallRule {
    param([string]$DisplayName, [int]$Port)

    $rule = Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue
    if ($rule) {
        # Enabled is boolean in modern PS
        if ($rule.Enabled -and $rule.Direction -eq "Inbound" -and $rule.Action -eq "Allow") {
            Say "$DisplayName already enabled (Inbound Allow)." "OK"
        } else {
            Say "$DisplayName exists but not enabled. Enabling..." "WARN"
            Enable-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue
            Say "$DisplayName enabled." "OK"
        }
    } else {
        New-NetFirewallRule -DisplayName $DisplayName -Direction Inbound -Protocol TCP `
            -LocalPort $Port -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
        Say "Created firewall rule: $DisplayName (Inbound TCP $Port Allow)" "OK"
    }
}

Ensure-FirewallRule -DisplayName "Splunk 9997" -Port $SplunkPort
Ensure-FirewallRule -DisplayName "Splunk 8000" -Port $WebPort

# ---------------- PHASE 4 : Verify listener ----------------
Say "Phase 4: Verify TCP listener on $SplunkPort" "STEP"

$hasListen = $false
try {
    $listenLines = netstat -ano | Select-String ":$SplunkPort\s+"
    foreach ($l in $listenLines) {
        if ($l.Line -match "LISTENING") {
            $hasListen = $true
            Say "LISTENING: $($l.Line.Trim())" "OK"
        }
    }
} catch {
    Say "netstat failed: $($_.Exception.Message)" "WARN"
}

if (-not $hasListen) {
    Say "No LISTENING socket on port $SplunkPort." "ERROR"
    Say "Manual fix: & '$script:SplunkExe' enable listen $SplunkPort -auth ${SplunkAdminUser}:${SplunkAdminPass}" "WARN"
    Say "Then: Restart-Service Splunkd" "WARN"
}

# Local TCP self-test
try {
    $t = Test-NetConnection -ComputerName "127.0.0.1" -Port $SplunkPort -WarningAction SilentlyContinue
    if ($t.TcpTestSucceeded) {
        Say "Local TCP 127.0.0.1:$SplunkPort reachable." "OK"
    } else {
        Say "Local TCP 127.0.0.1:$SplunkPort NOT reachable." "ERROR"
    }
} catch { }

# ---------------- PHASE 5 : Splunk Web ----------------
Say "Phase 5: Splunk Web check" "STEP"

try {
    $resp = Invoke-WebRequest -Uri "http://localhost:$WebPort" -TimeoutSec 5 -ErrorAction Stop
    if ($resp.StatusCode -eq 200) {
        Say "Splunk Web responding on http://localhost:$WebPort" "OK"
    }
} catch {
    Say "Splunk Web did not respond on port $WebPort: $($_.Exception.Message)" "WARN"
}

# ---------------- PHASE 6 : Active VM connections ----------------
Say "Phase 6: Active VM connections" "STEP"

$established = netstat -ano | Select-String ":$SplunkPort\s" | Where-Object { $_.Line -match "ESTABLISHED" }

if (-not $established) {
    Say "No ESTABLISHED connections on port $SplunkPort yet." "WARN"
    Say "Expected if the VMs are off or have not yet started forwarding." "INFO"
} else {
    foreach ($l in $established) {
        $lineTxt = $l.Line.Trim()
        if ($lineTxt -match "($VmSubnet\.\d+):(\d+)\s+ESTABLISHED") {
            Say "Connected from: $($Matches[1]) (source port $($Matches[2]))" "OK"
        } else {
            Say "ESTABLISHED: $lineTxt" "INFO"
        }
    }
}

# ---------------- PHASE 7 : Confirm data received ----------------
Say "Phase 7: Confirm data received in last 15 minutes" "STEP"

# Single-line SPL: required by splunk.exe CLI
$spl = 'index=main earliest=-15m | stats count by host | sort - count'
try {
    $out = Invoke-SplunkCli -CliArgs @("search", $spl)
    $found = $false
    foreach ($line in $out) {
        if ($line -match "\S") { Write-Host "    $line" -ForegroundColor Gray; $found = $true }
    }
    if (-not $found) {
        Say "No results from CLI query (or search returned quietly)." "INFO"
        Say "Check in Splunk Web: index=main earliest=-15m | stats count by host" "INFO"
    }
} catch {
    Say "CLI search failed: $($_.Exception.Message)" "WARN"
}

# ---------------- PHASE 8 : Hosts seen ----------------
Say "Phase 8: Hosts seen in index (via metadata)" "STEP"

$metaQuery = '| metadata type=hosts index=main | eval last_seen=strftime(lastTime,"%Y-%m-%d %H:%M:%S") | eval mins_ago=round((now()-lastTime)/60,1) | eval status=case(mins_ago<5,"UP",mins_ago<60,"IDLE",true(),"DOWN") | table host,status,mins_ago,last_seen,totalCount | sort host'
try {
    $out = Invoke-SplunkCli -CliArgs @("search", $metaQuery)
    foreach ($line in $out) {
        if ($line -match "\S") { Write-Host "    $line" -ForegroundColor Gray }
    }
} catch {
    Say "Metadata query failed: $($_.Exception.Message)" "WARN"
}

# ---------------- SUMMARY ----------------
Say "Host setup finished. Failures=$($script:Failures.Count) Warnings=$($script:Warnings.Count)" "STEP"

$svcNow = Get-SplunkService
Write-Host ""
Write-Host "Splunk Enterprise:" -ForegroundColor Cyan
Write-Host ("  Home       : {0}" -f $splunkHome)
Write-Host ("  Service    : {0}" -f $svcNow.Status)
Write-Host ("  Receiver   : TCP {0}" -f $SplunkPort)
Write-Host ("  Web UI     : http://localhost:{0}" -f $WebPort)
Write-Host ("  Login      : {0} / (password)" -f $SplunkAdminUser)
Write-Host ""
Write-Host "VMnet8 IP (this host on NAT network): $vmnet8IP" -ForegroundColor Cyan
Write-Host "VMs should forward to: ${vmnet8IP}:${SplunkPort}" -ForegroundColor Cyan
Write-Host ""

Write-Host "Splunk Web queries:" -ForegroundColor Green
Write-Host '  Is VM up?    index=main host=DC01-CORP earliest=-5m | stats count as events | eval status=if(events>0,"UP","DOWN") | table status,events'
Write-Host '  All hosts?   index=main earliest=-15m | stats count by host'
Write-Host '  Last seen?   | metadata type=hosts index=main | table host,lastTime,totalCount'
Write-Host ""

if ($script:Failures.Count -gt 0) {
    Write-Host "There were $($script:Failures.Count) failure(s). Review the log above." -ForegroundColor Red
}

try { Stop-Transcript | Out-Null } catch { }

if (-not $NoPrompt) { Read-Host "Press Enter to exit" }
if ($script:Failures.Count -gt 0) { exit 2 } else { exit 0 }