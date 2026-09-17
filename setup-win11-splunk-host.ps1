<#
.SYNOPSIS
    SOC Lab - Win 11 Host Side Splunk Enterprise Setup.

.DESCRIPTION
    Runs on the Win 11 host where Splunk Enterprise is installed.
    - Verifies Splunk Enterprise service
    - Enables receiving on port 9997 (idempotent)
    - Opens Windows Firewall for 9997 and 8000
    - Verifies the listener is bound
    - Confirms Splunk Web is reachable
    - Shows live connections from VMs (Windows Server / Ubuntu)
    - Prints the exact SPL queries to verify logs are arriving

    Does NOT touch the VMs. Does NOT install anything.
    Idempotent - safe to run anytime.

.PARAMETER SplunkAdminUser
    Splunk admin username. Default socadmin.

.PARAMETER SplunkAdminPass
    Splunk admin password. Default P@ssw0rd2026!.

.PARAMETER SplunkPort
    Receiving port. Default 9997.

.PARAMETER WebPort
    Splunk Web port. Default 8000.

.PARAMETER VmSubnet
    VMnet8 subnet prefix to filter ESTABLISHED connections. Default 192.168.10.

.EXAMPLE
    .\setup-win11-splunk-host.ps1
#>

[CmdletBinding()]
param(
    [string]$SplunkAdminUser = "socadmin",
    [string]$SplunkAdminPass = "P@ssw0rd2026!",
    [int]   $SplunkPort      = 9997,
    [int]   $WebPort         = 8000,
    [string]$VmSubnet        = "192.168.10"
)

$ErrorActionPreference = "Continue"
$script:Failures = @()
$script:Warnings = @()

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
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Find-SplunkHome {
    $candidates = @(
        "C:\Program Files\Splunk",
        "C:\Program Files\SplunkUniversalForwarder",
        "D:\Program Files\Splunk",
        "E:\Program Files\Splunk"
    )
    foreach ($c in $candidates) {
        if (Test-Path (Join-Path $c "bin\splunk.exe")) { return $c }
    }
    # Fall back to registry
    try {
        $reg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Splunk" -ErrorAction SilentlyContinue
        if ($reg -and $reg.InstallPath) {
            if (Test-Path (Join-Path $reg.InstallPath "bin\splunk.exe")) { return $reg.InstallPath }
        }
    } catch { }
    return $null
}

function Get-SplunkService {
    return Get-Service -Name "Splunkd" -ErrorAction SilentlyContinue
}

# ============================================================
# BANNER
# ============================================================
Write-Host ""
Write-Host "##############################################################" -ForegroundColor Magenta
Write-Host "#   SOC Lab - Win 11 Host Splunk Enterprise Setup           #" -ForegroundColor Magenta
Write-Host "##############################################################" -ForegroundColor Magenta
Write-Host ""

# ============================================================
# PHASE 0 - Sanity
# ============================================================
Say "Phase 0: Sanity" "STEP"

if (-not (Test-Admin)) {
    Say "Not running as Administrator. Reopen PowerShell as Admin." "ERROR"
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}
Say "Administrator confirmed." "OK"

$splunkHome = Find-SplunkHome
if (-not $splunkHome) {
    Say "Splunk Enterprise not found. Looked in Program Files and registry." "ERROR"
    Write-Host ""
    Write-Host "Install Splunk Enterprise from https://www.splunk.com/en_us/download/splunk-enterprise.html" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}
Say "Splunk Enterprise found at: $splunkHome" "OK"

$splunkExe = Join-Path $splunkHome "bin\splunk.exe"

# Detect VMnet8 IP
$vmnet8IP = $null
try {
    $vmnet8 = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceAlias -match "VMnet8" -and $_.IPAddress -like "$VmSubnet.*" } |
        Select-Object -First 1
    if ($vmnet8) { $vmnet8IP = $vmnet8.IPAddress }
} catch { }

if ($vmnet8IP) {
    Say "VMnet8 adapter IP: $vmnet8IP" "OK"
} else {
    Say "VMnet8 adapter with $VmSubnet.x IP not found." "WARN"
}

# ============================================================
# PHASE 1 - Splunk service
# ============================================================
Say "Phase 1: Splunk Enterprise service" "STEP"

$svc = Get-SplunkService
if (-not $svc) {
    Say "Splunkd service not found." "ERROR"
    Read-Host "Press Enter to exit"
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
        Read-Host "Press Enter to exit"
        exit 1
    }
}

# ============================================================
# PHASE 2 - Enable receiver on 9997
# ============================================================
Say "Phase 2: Enable TCP receiver on port $SplunkPort" "STEP"

# Check current state via inputs.conf
$localDir  = Join-Path $splunkHome "etc\system\local"
$inputsConf = Join-Path $localDir "inputs.conf"
$receiverStanza = "[splunktcp://$SplunkPort]"

$alreadyEnabled = $false
if (Test-Path $inputsConf) {
    $content = Get-Content $inputsConf -Raw
    if ($content -match [regex]::Escape($receiverStanza)) {
        $alreadyEnabled = $true
    }
}

if ($alreadyEnabled) {
    Say "Receiver stanza already present in inputs.conf." "OK"
} else {
    Say "Adding receiver via splunk.exe enable listen..." "INFO"
    & $splunkExe enable listen $SplunkPort -auth "${SplunkAdminUser}:${SplunkAdminPass}" 2>&1 |
        ForEach-Object { Say $_ "INFO" }

    Say "Restarting Splunkd to apply..." "INFO"
    & $splunkExe restart 2>&1 | ForEach-Object { Say $_ "INFO" }
    Start-Sleep 30
}

# Ensure [splunktcp://9997] stanza exists in inputs.conf as a safety net
if (-not (Test-Path $inputsConf)) {
    New-Item -ItemType Directory -Path $localDir -Force | Out-Null
    Set-Content -Path $inputsConf -Value "[splunktcp://$SplunkPort]`r`nconnection_host = ip`r`n" -Encoding ASCII
    Say "Created inputs.conf with receiver stanza." "OK"
    Restart-Service Splunkd -Force -ErrorAction SilentlyContinue
    Start-Sleep 30
} elseif (-not ((Get-Content $inputsConf -Raw) -match [regex]::Escape($receiverStanza))) {
    Add-Content -Path $inputsConf -Value "`r`n$receiverStanza`r`nconnection_host = ip`r`n" -Encoding ASCII
    Say "Appended receiver stanza to inputs.conf." "OK"
    Restart-Service Splunkd -Force -ErrorAction SilentlyContinue
    Start-Sleep 30
}

# Verify with splunk.exe
Say "Verifying receiver via splunk.exe..." "INFO"
$listenOut = & $splunkExe display listen 2>&1
foreach ($line in $listenOut) {
    if ($line -match "Receiving") { Say $line "OK" }
}

# ============================================================
# PHASE 3 - Windows Firewall
# ============================================================
Say "Phase 3: Windows Firewall" "STEP"

function Ensure-FirewallRule {
    param([string]$DisplayName, [int]$Port)

    $rule = Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue
    if ($rule) {
        if ($rule.Enabled -eq "True" -and $rule.Direction -eq "Inbound" -and $rule.Action -eq "Allow") {
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

# ============================================================
# PHASE 4 - Verify listener on 9997
# ============================================================
Say "Phase 4: Verify TCP listener on $SplunkPort" "STEP"

$listenLines = netstat -ano | Select-String ":$SplunkPort\s"
$hasListen = $false
foreach ($l in $listenLines) {
    if ($l.Line -match "LISTENING") {
        $hasListen = $true
        Say "LISTENING: $($l.Line.Trim())" "OK"
    }
}

if (-not $hasListen) {
    Say "No LISTENING socket on port $SplunkPort." "ERROR"
    Say "Try: & '$splunkExe' enable listen $SplunkPort -auth ${SplunkAdminUser}:${SplunkAdminPass}" "WARN"
    Say "Then: Restart-Service Splunkd" "WARN"
}

# ============================================================
# PHASE 5 - Splunk Web check
# ============================================================
Say "Phase 5: Splunk Web check" "STEP"

try {
    $resp = Invoke-WebRequest -Uri "http://localhost:$WebPort" -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
    if ($resp.StatusCode -eq 200) {
        Say "Splunk Web is responding on http://localhost:$WebPort" "OK"
    }
} catch {
    Say "Splunk Web did not respond on port $WebPort: $($_.Exception.Message)" "WARN"
}

# ============================================================
# PHASE 6 - Show active connections from VMs
# ============================================================
Say "Phase 6: Active VM connections" "STEP"

$established = netstat -ano | Select-String ":$SplunkPort\s" | Where-Object { $_.Line -match "ESTABLISHED" }

if (-not $established) {
    Say "No ESTABLISHED connections on port $SplunkPort yet." "WARN"
    Say "That is expected if the VMs are off or have not yet started forwarding." "INFO"
} else {
    foreach ($l in $established) {
        if ($l.Line -match "($VmSubnet\.\d+):(\d+)\s+ESTABLISHED") {
            $remote = $Matches[1]
            $port   = $Matches[2]
            Say "Connected from: $remote (source port $port)" "OK"
        } else {
            Say "ESTABLISHED: $($l.Line.Trim())" "INFO"
        }
    }
}

# ============================================================
# PHASE 7 - Confirm data being received (via splunkd CLI)
# ============================================================
Say "Phase 7: Confirm data received in last 15 minutes" "STEP"

$spl = @'
index=main earliest=-15m
| stats count by host
| sort - count
'@

try {
    Say "Querying index=main for events received in last 15 minutes..." "INFO"
    $out = & $splunkExe search $spl "-auth" "${SplunkAdminUser}:${SplunkAdminPass}" 2>&1
    $found = $false
    foreach ($line in $out) {
        if ($line -match "\d+ results|host") {
            Write-Host "    $line" -ForegroundColor Gray
            $found = $true
        }
    }
    if (-not $found) {
        Say "No results from CLI query (or search returned quietly)." "INFO"
        Say "Check in Splunk Web: index=main earliest=-15m | stats count by host" "INFO"
    }
} catch {
    Say "CLI search failed: $($_.Exception.Message)" "WARN"
}

# ============================================================
# PHASE 8 - Show known hosts from index metadata
# ============================================================
Say "Phase 8: Hosts seen in index (via metadata)" "STEP"

$metaQuery = @'
| metadata type=hosts index=main
| eval last_seen = strftime(lastTime, "%Y-%m-%d %H:%M:%S")
| eval mins_ago = round((now() - lastTime)/60, 1)
| eval status = case(mins_ago < 5, "UP", mins_ago < 60, "IDLE", true(), "DOWN")
| table host, status, mins_ago, last_seen, totalCount
| sort host
'@

try {
    & $splunkExe search $metaQuery "-auth" "${SplunkAdminUser}:${SplunkAdminPass}" 2>&1 |
        ForEach-Object { if ($_ -match "\S") { Write-Host "    $_" -ForegroundColor Gray } }
} catch {
    Say "Metadata query failed: $($_.Exception.Message)" "WARN"
}

# ============================================================
# SUMMARY
# ============================================================
Say "Host setup finished. Failures=$($script:Failures.Count) Warnings=$($script:Warnings.Count)" "STEP"

Write-Host ""
Write-Host "Splunk Enterprise:" -ForegroundColor Cyan
Write-Host ("  Home       : {0}" -f $splunkHome)
Write-Host ("  Service    : {0}" -f (Get-SplunkService).Status)
Write-Host ("  Receiver   : TCP {0}" -f $SplunkPort)
Write-Host ("  Web UI     : http://localhost:{0}" -f $WebPort)
Write-Host ("  Login      : {0} / (password)" -f $SplunkAdminUser)
Write-Host ""
Write-Host "VMnet8 IP (this host on NAT network): $vmnet8IP" -ForegroundColor Cyan
Write-Host "VMs should forward to: ${vmnet8IP}:${SplunkPort}" -ForegroundColor Cyan
Write-Host ""

Write-Host "Verify in browser:" -ForegroundColor Green
Write-Host "  http://localhost:$WebPort  ->  Search & Reporting"
Write-Host ""
Write-Host "Status of all hosts (run in Splunk Web):" -ForegroundColor Green
Write-Host '  | metadata type=hosts index=main'
Write-Host '  | eval status = if((now()-lastTime) < 300, "UP", "DOWN")'
Write-Host '  | table host, status, lastTime, totalCount'
Write-Host ""
Write-Host "Check Windows Server 2022 VM specifically:" -ForegroundColor Green
Write-Host '  index=main host=DC01-CORP earliest=-5m'
Write-Host '  | stats count as events'
Write-Host '  | eval status = if(events > 0, "UP", "DOWN")'
Write-Host '  | table status, events'
Write-Host ""
Write-Host "Check Ubuntu VM specifically:" -ForegroundColor Green
Write-Host '  index=main host=srv-linux-01 earliest=-5m'
Write-Host '  | stats count as events'
Write-Host '  | eval status = if(events > 0, "UP", "DOWN")'
Write-Host '  | table status, events'
Write-Host ""

if ($script:Failures.Count -gt 0) {
    Write-Host "There were $($script:Failures.Count) failure(s). Review the log above." -ForegroundColor Red
}

Write-Host ""
Read-Host "Press Enter to exit"
