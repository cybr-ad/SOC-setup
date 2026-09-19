<#
.SYNOPSIS
    SOC Lab - Windows Server 2022 Splunk Forwarder Setup (with log file monitor).

.DESCRIPTION
    Runs inside Windows Server 2022 as Administrator.
    - Ensures hostname is DC01-CORP (renames + reboots + auto-resumes).
    - Sets static IP + gateway + DNS (idempotent).
    - Stages class files, installs Sysmon + Splunk UF.
    - Writes inputs.conf (host = DC01-CORP) and outputs.conf -> Splunk server.
    - PROMPTS FOR A CUSTOM LOG FILE and adds it as a monitor stanza.
    - Starts the SplunkForwarder service, enables auditing, verifies TCP.

.PARAMETER LogFile
    Full path to a log file to monitor (e.g., C:\Logs\windows_attacks_sample.log).
    If omitted, the script will prompt for it.
    Pass "skip" to skip adding a custom log file.

.PARAMETER Sourcetype
    Sourcetype for the custom log file. Default windows_attacks.

.PARAMETER Index
    Index for the custom log file. Default main.

.PARAMETER CopyFrom
    Optional source path to copy FROM (e.g., a sample file in class file\samples\).
    If set and LogFile doesn't exist, it copies from this path first.
#>

[CmdletBinding()]
param(
    [string]$SplunkServerIP = "192.168.10.1",
    [int]   $SplunkPort     = 9997,
    [string]$ServerIP       = "192.168.10.20",
    [int]   $PrefixLength   = 24,
    [string]$Gateway        = "192.168.10.2",
    [string]$InterfaceAlias = "Ethernet0",
    [string]$LabRoot        = "C:\SOC-Lab",
    [string]$TargetHostname = "DC01-CORP",
    [string]$LogFile        = "",
    [string]$Sourcetype     = "windows_attacks",
    [string]$Index          = "main",
    [string]$CopyFrom       = "",
    [switch]$SkipNetworkConfig,
    [switch]$SkipRename,
    [switch]$SkipAuditing
)

$ErrorActionPreference = "Continue"
$script:Failures = @()
$script:Warnings = @()
$TaskName = "SOC-Lab-Resume-After-Rename"
$script:LogFile = $null
$script:Transcript = $null

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

function Test-WindowsServer {
    $os = Get-CimInstance Win32_OperatingSystem
    return ($os.ProductType -ne 1)
}

function Ensure-Folder {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Find-ClassRoot {
    param([string]$Start)
    $checks = @()
    if ($Start) {
        $checks += $Start
        $checks += (Split-Path $Start -Parent)
        $checks += (Join-Path $Start "class file")
    }
    $checks += "C:\Users\Administrator\Desktop\class file"
    $checks += "C:\Users\Administrator\Desktop\class file\class file"
    $checks += "C:\SOC-Lab"

    if ($Start) {
        $p = $Start
        for ($i = 0; $i -lt 5; $i++) {
            $p = Split-Path $p -Parent
            if (-not $p) { break }
            $checks += $p
            $checks += (Join-Path $p "class file")
        }
    }

    foreach ($c in $checks) {
        if (-not $c) { continue }
        if (Test-Path (Join-Path $c "bin\splunkforwarder.msi")) { return $c }
        if (Test-Path (Join-Path $c "configs\windows\inputs.conf")) { return $c }
    }
    return $null
}

# ============================================================
# BOOTSTRAP
# ============================================================
Ensure-Folder $LabRoot
Ensure-Folder (Join-Path $LabRoot "Logs")
Ensure-Folder (Join-Path $LabRoot "Backups")

$script:LogFile = Join-Path $LabRoot ("Logs\Setup-{0}.log" -f (Get-Date -Format "yyyyMMdd_HHmmss"))

try {
    $script:Transcript = Join-Path $LabRoot ("Logs\Setup-transcript-{0}.txt" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
    Start-Transcript -Path $script:Transcript -Force -ErrorAction SilentlyContinue | Out-Null
} catch { }

Write-Host ""
Write-Host "##############################################################" -ForegroundColor Magenta
Write-Host "#  SOC Lab - Windows Server 2022 Forwarder Setup            #" -ForegroundColor Magenta
Write-Host "#  Target hostname: $TargetHostname" -ForegroundColor Magenta
Write-Host "##############################################################" -ForegroundColor Magenta
Write-Host ""

$here = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
Say "Script folder: $here"
Say "Current OS hostname: $env:COMPUTERNAME"
Say "Log: $script:LogFile"

# ============================================================
# PHASE 0 - Sanity
# ============================================================
Say "Phase 0: Sanity checks" "STEP"

if (-not (Test-Admin)) {
    Say "Not running as Administrator. Reopen PowerShell as Admin." "ERROR"
    exit 1
}
Say "Administrator confirmed." "OK"

if (-not (Test-WindowsServer)) {
    Say "This is not Windows Server. Aborting." "ERROR"
    exit 1
}
Say "Windows Server confirmed." "OK"

# ============================================================
# PHASE 0.5 - Hostname enforcement
# ============================================================
Say "Phase 0.5: Hostname enforcement" "STEP"

$currentHost = $env:COMPUTERNAME

if ($SkipRename) {
    Say "SkipRename specified. Leaving hostname as $currentHost." "WARN"
}
elseif ($currentHost -ieq $TargetHostname) {
    Say "Hostname already $TargetHostname. Nothing to do." "OK"
    try {
        $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($t) {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
            Say "Removed leftover resume task." "OK"
        }
    } catch { }
}
else {
    Say "Hostname is '$currentHost', renaming to '$TargetHostname'." "WARN"

    $scriptSource = $PSCommandPath
    if (-not $scriptSource) { $scriptSource = $MyInvocation.MyCommand.Path }
    if (-not $scriptSource) { $scriptSource = $here + "\" + "Setup-SOC-WinServer2022.ps1" }

    $preservedScript = Join-Path $LabRoot "Setup-SOC-WinServer2022.ps1"
    try {
        Copy-Item -Path $scriptSource -Destination $preservedScript -Force -ErrorAction Stop
        Say "Preserved script copy: $preservedScript" "OK"
    } catch {
        Say "Could not copy script to $preservedScript : $($_.Exception.Message)" "WARN"
        $preservedScript = $scriptSource
    }

    $argList = @(
        "-NoProfile",
        "-NoLogo",
        "-ExecutionPolicy", "Bypass",
        "-WindowStyle", "Hidden",
        "-File", "`"$preservedScript`"",
        "-SplunkServerIP", $SplunkServerIP,
        "-SplunkPort", $SplunkPort,
        "-ServerIP", $ServerIP,
        "-PrefixLength", $PrefixLength,
        "-Gateway", $Gateway,
        "-InterfaceAlias", $InterfaceAlias,
        "-LabRoot", "`"$LabRoot`"",
        "-TargetHostname", $TargetHostname,
        "-Sourcetype", $Sourcetype,
        "-Index", $Index
    )
    if ($SkipNetworkConfig) { $argList += "-SkipNetworkConfig" }
    if ($SkipAuditing)      { $argList += "-SkipAuditing" }
    if ($LogFile)           { $argList += @("-LogFile", "`"$LogFile`"") }
    if ($CopyFrom)          { $argList += @("-CopyFrom", "`"$CopyFrom`"") }

    $resumeArgs = $argList -join " "

    try {
        $action    = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $resumeArgs
        $trigger   = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 1)

        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
            -Principal $principal -Settings $settings -Force -ErrorAction Stop | Out-Null

        Say "Resume task registered: $TaskName" "OK"
    } catch {
        Say "Could not register resume task: $($_.Exception.Message)" "ERROR"
        try { Stop-Transcript | Out-Null } catch { }
        exit 2
    }

    Say "Renaming to $TargetHostname and rebooting in 15 seconds..." "WARN"
    Start-Sleep 15

    try {
        Rename-Computer -NewName $TargetHostname -Force -ErrorAction Stop
        try { Stop-Transcript | Out-Null } catch { }
        Restart-Computer -Force
    } catch {
        Say "Say Rename/restart failed: $($_.Exception.Message)" "ERROR"
    }

    exit 0
}

# ============================================================
# PHASE 1 - Stage files
# ============================================================
Say "Phase 1: Stage class files into $LabRoot" "STEP"

$ClassRoot = Find-ClassRoot -Start $here
if (-not $ClassRoot) {
    Say "class file folder not found. Using $LabRoot as fallback." "WARN"
    $ClassRoot = $LabRoot
} else {
    Say "class file folder: $ClassRoot" "OK"
}

$stageMap = @(
    @{ Src = "bin\splunkforwarder.msi";                 Dst = "$LabRoot\splunkforwarder.msi" },
    @{ Src = "bin\sysmon\Sysmon64.exe";                 Dst = "$LabRoot\Sysmon64.exe" },
    @{ Src = "configs\windows\sysmonconfig-export.xml"; Dst = "$LabRoot\sysmonconfig-export.xml" }
)

foreach ($m in $stageMap) {
    $src = Join-Path $ClassRoot $m.Src
    if (Test-Path $src) {
        try {
            Copy-Item -Path $src -Destination $m.Dst -Force -ErrorAction Stop
            Say "Staged: $($m.Src)" "OK"
        } catch {
            Say "Copy failed for $($m.Src): $($_.Exception.Message)" "WARN"
        }
    } else {
        Say "Not found (optional): $src" "WARN"
    }
}

if (-not (Test-Path "$LabRoot\splunkforwarder.msi")) {
    Say "splunkforwarder.msi missing. Cannot continue." "ERROR"
    try { Stop-Transcript | Out-Null } catch { }
    exit 1
}
Say "MSI present." "OK"

# ============================================================
# PHASE 1.5 - Ask for the log file to monitor
# ============================================================
Say "Phase 1.5: Custom log file" "STEP"

if ([string]::IsNullOrWhiteSpace($LogFile)) {
    Write-Host ""
    Write-Host "Enter the full path to the log file you want to forward." -ForegroundColor Cyan
    Write-Host "Examples:" -ForegroundColor DarkGray
    Write-Host "  C:\Logs\windows_attacks_sample.log" -ForegroundColor DarkGray
    Write-Host "  $LabRoot\windows_attacks_sample.log" -ForegroundColor DarkGray
    Write-Host "  (type 'skip' to not add a custom log file)" -ForegroundColor DarkGray
    Write-Host ""
    $LogFile = (Read-Host "Log file path").Trim()
}

if ($LogFile -ieq "skip" -or [string]::IsNullOrWhiteSpace($LogFile)) {
    Say "No custom log file will be monitored." "WARN"
    $LogFile = ""
} else {
    Say "Log file selected: $LogFile"

    # If CopyFrom is provided and LogFile doesn't exist, copy it
    if (-not (Test-Path $LogFile)) {
        if (-not [string]::IsNullOrWhiteSpace($CopyFrom) -and (Test-Path $CopyFrom)) {
            Say "Log file not found. Copying from: $CopyFrom"
            $logDir = Split-Path $LogFile -Parent
            if ($logDir -and -not (Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            try {
                Copy-Item -Path $CopyFrom -Destination $LogFile -Force -ErrorAction Stop
                Say "Copied to $LogFile" "OK"
            } catch {
                Say "Failed to copy: $($_.Exception.Message)" "ERROR"
                $LogFile = ""
            }
        } else {
            # Try to auto-find it in the class file\samples folder
            $candidate = Join-Path $ClassRoot "samples\windows_attacks_sample.log"
            if (Test-Path $candidate) {
                Say "Log file not found. Copying from class file\samples: $candidate"
                $logDir = Split-Path $LogFile -Parent
                if ($logDir -and -not (Test-Path $logDir)) {
                    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
                }
                try {
                    Copy-Item -Path $candidate -Destination $LogFile -Force -ErrorAction Stop
                    Say "Copied to $LogFile" "OK"
                } catch {
                    Say "Failed to copy: $($_.Exception.Message)" "WARN"
                    $LogFile = ""
                }
            } else {
                Say "Log file does not exist: $LogFile" "ERROR"
                Say "And no source found to copy from." "ERROR"
                $LogFile = ""
            }
        }
    } else {
        Say "Log file exists." "OK"
    }

    if ($LogFile) {
        # Fix permissions so splunk user can read
        try {
            $acl = Get-Acl $LogFile
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                "SYSTEM", "Read", "Allow")
            $acl.SetAccessRule($rule)
            Set-Acl -Path $LogFile -AclObject $acl
            Say "Granted SYSTEM read access to $LogFile" "OK"
        } catch {
            Say "Could not adjust ACL: $($_.Exception.Message)" "WARN"
        }
    }
}

# ============================================================
# PHASE 2 - Network
# ============================================================
if (-not $SkipNetworkConfig) {
    Say "Phase 2: Network configuration" "STEP"

    $adapter = Get-NetAdapter -Name $InterfaceAlias -ErrorAction SilentlyContinue
    if (-not $adapter) {
        Say "Adapter '$InterfaceAlias' not found. Available adapters:" "WARN"
        Get-NetAdapter | Select-Object Name, Status | Format-Table | Out-String | Write-Host
    } else {
        $cur = @(Get-NetIPAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue)
        $hasTarget = $false
        foreach ($ip in $cur) { if ($ip.IPAddress -eq $ServerIP) { $hasTarget = $true } }

        if ($hasTarget) {
            Say "IP $ServerIP already configured." "OK"
        } else {
            foreach ($ip in $cur) {
                try { Remove-NetIPAddress -InputObject $ip -Confirm:$false -ErrorAction SilentlyContinue } catch { }
            }
            Get-NetRoute -InterfaceAlias $InterfaceAlias -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
                Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue

            try {
                New-NetIPAddress -InterfaceAlias $InterfaceAlias `
                    -IPAddress $ServerIP -PrefixLength $PrefixLength `
                    -DefaultGateway $Gateway -ErrorAction Stop | Out-Null
                Say "Set IP $ServerIP/$PrefixLength gw $Gateway" "OK"
            } catch {
                Say "Failed to set IP: $($_.Exception.Message)" "ERROR"
            }
        }

        try {
            Set-DnsClientServerAddress -InterfaceAlias $InterfaceAlias `
                -ServerAddresses ("1.1.1.1","8.8.8.8") -ErrorAction Stop
            Say "DNS -> 1.1.1.1 / 8.8.8.8" "OK"
        } catch {
            Say "DNS set failed: $($_.Exception.Message)" "WARN"
        }
    }
} else {
    Say "Phase 2: skipped." "INFO"
}

# ============================================================
# PHASE 3 - Sysmon
# ============================================================
Say "Phase 3: Sysmon" "STEP"

$sysmonExe = Join-Path $LabRoot "Sysmon64.exe"
$sysmonCfg = Join-Path $LabRoot "sysmonconfig-export.xml"
$sysmonSvc = Get-Service -Name "Sysmon64","Sysmon" -ErrorAction SilentlyContinue | Select-Object -First 1

if ((Test-Path $sysmonExe) -and (Test-Path $sysmonCfg)) {
    if ($sysmonSvc) {
        Say "Sysmon present. Updating config..." "INFO"
        & $sysmonExe -c $sysmonCfg 2>&1 | ForEach-Object { Say $_ "INFO" }
        Say "Sysmon config updated." "OK"
    } else {
        Say "Installing Sysmon..." "INFO"
        & $sysmonExe -accepteula -i $sysmonCfg 2>&1 | ForEach-Object { Say $_ "INFO" }
        Start-Sleep 5
        $sysmonSvc = Get-Service -Name "Sysmon64","Sysmon" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($sysmonSvc) { Say "Sysmon installed." "OK" }
        else            { Say "Sysmon service not present after install." "WARN" }
    }
} else {
    Say "Sysmon files not staged. Skipping." "WARN"
}

# ============================================================
# PHASE 4 - Splunk UF install
# ============================================================
Say "Phase 4: Splunk Universal Forwarder" "STEP"

$ufHome = "C:\Program Files\SplunkUniversalForwarder"
$ufExe  = Join-Path $ufHome "bin\splunk.exe"
$ufMsi  = Join-Path $LabRoot "splunkforwarder.msi"

if (Test-Path $ufExe) {
    Say "UF already installed at $ufHome" "OK"
} else {
    Say "Installing UF from MSI..." "INFO"
    $msiArgs = @(
        "/i", "`"$ufMsi`"",
        "AGREETOLICENSE=Yes",
        "SPLUNKUSERNAME=admin",
        "SPLUNKPASSWORD=P@ssw0rd2026!",
        "RECEIVING_INDEXER=${SplunkServerIP}:${SplunkPort}",
        "LAUNCHSPLUNK=1",
        "/quiet", "/norestart",
        "/L*v", "`"$LabRoot\Logs\uf-msi-install.log`""
    )
    $proc = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru
    Say "msiexec exit code: $($proc.ExitCode)" "INFO"

    for ($i = 0; $i -lt 24; $i++) {
        if (Test-Path $ufExe) { break }
        Start-Sleep 5
    }

    if (Test-Path $ufExe) {
        Say "UF installed." "OK"
    } else {
        Say "UF still missing. See $LabRoot\Logs\uf-msi-install.log" "ERROR"
        try { Stop-Transcript | Out-Null } catch { }
        exit 1
    }
}

# ============================================================
# PHASE 5 - inputs.conf + outputs.conf
# ============================================================
Say "Phase 5: UF configuration" "STEP"

$localDir = Join-Path $ufHome "etc\system\local"
Ensure-Folder $localDir

foreach ($f in @("inputs.conf","outputs.conf")) {
    $p = Join-Path $localDir $f
    if (Test-Path $p) {
        $b = Join-Path $LabRoot ("Backups\{0}_{1}" -f (Get-Date -Format "yyyyMMdd_HHmmss"), $f)
        try { Copy-Item -Path $p -Destination $b -Force -ErrorAction SilentlyContinue } catch { }
        Say "Backed up $f" "INFO"
    }
}

# outputs.conf
$outputsLines = @(
    "[tcpout]",
    "defaultGroup = primary_indexers",
    "",
    "[tcpout:primary_indexers]",
    "server = ${SplunkServerIP}:${SplunkPort}",
    "useACK = false"
)
Set-Content -Path (Join-Path $localDir "outputs.conf") -Value $outputsLines -Encoding ASCII -Force
Say "outputs.conf -> ${SplunkServerIP}:${SplunkPort}" "OK"

# inputs.conf
$inputsLines = @(
    "[default]",
    "host = $TargetHostname",
    "",
    "[WinEventLog://Security]",
    "disabled = 0",
    "start_from = oldest",
    "current_only = 0",
    "index = main",
    "renderXml = true",
    "",
    "[WinEventLog://System]",
    "disabled = 0",
    "index = main",
    "",
    "[WinEventLog://Application]",
    "disabled = 0",
    "index = main",
    "",
    "[WinEventLog://Microsoft-Windows-Sysmon/Operational]",
    "disabled = 0",
    "index = main",
    "renderXml = true",
    "",
    "[WinEventLog://Microsoft-Windows-PowerShell/Operational]",
    "disabled = 0",
    "index = main",
    "renderXml = true",
    "",
    "[WinEventLog://Windows PowerShell]",
    "disabled = 0",
    "index = main",
    "",
    "[WinEventLog://Directory Service]",
    "disabled = 0",
    "index = main",
    "",
    "[WinEventLog://DNS Server]",
    "disabled = 0",
    "index = main",
    "",
    "[WinEventLog://Microsoft-Windows-Windows Defender/Operational]",
    "disabled = 0",
    "index = main",
    "renderXml = true"
)

# Add the custom log file monitor
if ($LogFile) {
    $inputsLines += ""
    $inputsLines += "[monitor://$LogFile]"
    $inputsLines += "disabled = 0"
    $inputsLines += "sourcetype = $Sourcetype"
    $inputsLines += "index = $Index"
    Say "Added monitor stanza for: $LogFile" "OK"
}

Set-Content -Path (Join-Path $localDir "inputs.conf") -Value $inputsLines -Encoding ASCII -Force
Say "inputs.conf written with host = $TargetHostname" "OK"

# ============================================================
# PHASE 6 - Service
# ============================================================
Say "Phase 6: SplunkForwarder service" "STEP"

$svc = Get-Service -Name "SplunkForwarder" -ErrorAction SilentlyContinue

if (-not $svc) {
    Say "Service missing. Running 'enable boot-start'..." "WARN"
    & $ufExe enable boot-start -user SYSTEM -auth "admin:P@ssw0rd2026!" 2>&1 |
        ForEach-Object { Say $_ "INFO" }
    for ($i = 0; $i -lt 12; $i++) {
        Start-Sleep 5
        $svc = Get-Service -Name "SplunkForwarder" -ErrorAction SilentlyContinue
        if ($svc) { break }
    }
}

if ($svc) {
    try {
        if ($svc.Status -eq "Running") { Restart-Service SplunkForwarder -Force }
        else                            { Start-Service   SplunkForwarder }
        Start-Sleep 10
        $svc = Get-Service -Name "SplunkForwarder" -ErrorAction SilentlyContinue
        Say "SplunkForwarder status: $($svc.Status)" "OK"
    } catch {
        Say "Service start failed: $($_.Exception.Message)" "ERROR"
    }
} else {
    Say "SplunkForwarder service not present." "ERROR"
}

# ============================================================
# PHASE 7 - Auditing
# ============================================================
if (-not $SkipAuditing) {
    Say "Phase 7: Advanced auditing" "STEP"

    $regAudit = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    if (-not (Test-Path $regAudit)) { New-Item -Path $regAudit -Force | Out-Null }
    Set-ItemProperty -Path $regAudit -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord
    Say "CmdLine logging enabled (4688)." "OK"

    $regPS = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    if (-not (Test-Path $regPS)) { New-Item -Path $regPS -Force | Out-Null }
    Set-ItemProperty -Path $regPS -Name "EnableScriptBlockLogging" -Value 1 -Type DWord
    Say "PS ScriptBlock logging enabled (4104)." "OK"

    $auditSubs = @(
        @("Process Creation","success:enable","failure:disable"),
        @("Logon","success:enable","failure:enable"),
        @("Logoff","success:enable","failure:disable"),
        @("Account Lockout","success:enable","failure:enable"),
        @("User Account Management","success:enable","failure:enable"),
        @("Security Group Management","success:enable","failure:enable"),
        @("Special Logon","success:enable","failure:disable"),
        @("Credential Validation","success:enable","failure:enable"),
        @("Audit Policy Change","success:enable","failure:enable")
    )
    foreach ($a in $auditSubs) {
        $cmd = "auditpol /set /subcategory:`"$($a[0])`" /$($a[1]) /$($a[2])"
        cmd.exe /c $cmd | Out-Null
    }
    Say "auditpol applied." "OK"
} else {
    Say "Phase 7: skipped." "INFO"
}

# ============================================================
# PHASE 8 - Verify
# ============================================================
Say "Phase 8: Verification" "STEP"

$tcpOK = $false
for ($attempt = 1; $attempt -le 3; $attempt++) {
    try {
        $tcp = Test-NetConnection -ComputerName $SplunkServerIP -Port $SplunkPort -WarningAction SilentlyContinue
        if ($tcp.TcpTestSucceeded) { $tcpOK = $true; break }
    } catch { }
    if ($attempt -lt 3) { Start-Sleep 5 }
}

if ($tcpOK) {
    Say "TCP ${SplunkServerIP}:${SplunkPort} reachable." "OK"
} else {
    Say "TCP ${SplunkServerIP}:${SplunkPort} NOT reachable." "ERROR"
}

$hostLine = Select-String -Path (Join-Path $localDir "inputs.conf") -Pattern "^host\s*=" | Select-Object -First 1
if ($hostLine) { Say "inputs.conf host -> $($hostLine.Line.Trim())" "OK" }

# Show what monitors are active
Say "Active monitors:" "INFO"
$monitorLines = Select-String -Path (Join-Path $localDir "inputs.conf") -Pattern "^\[monitor://" |
    ForEach-Object { $_.Line }
foreach ($m in $monitorLines) { Say "    $m" "INFO" }

Say "OS hostname -> $env:COMPUTERNAME (expected: $TargetHostname)" "INFO"

# Append a fresh line to the custom log so Splunk reads it
if ($LogFile -and (Test-Path $LogFile)) {
    try {
        $stamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Add-Content -Path $LogFile -Value "FORCE-READ $stamp" -Encoding ASCII -ErrorAction Stop
        Say "Appended test line to $LogFile" "OK"
    } catch {
        Say "Could not append test line: $($_.Exception.Message)" "WARN"
    }
}

try {
    $stamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    Write-EventLog -LogName Application -Source "Application" -EventId 9999 `
        -EntryType Information -Message "HOSTNAME-CONFIRM $TargetHostname $stamp" -ErrorAction Stop
    Say "Marker event written (EventID 9999)." "OK"
} catch {
    Say "Could not write marker event: $($_.Exception.Message)" "WARN"
}

try {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Say "Resume task cleared." "INFO"
} catch { }

# ============================================================
# SUMMARY
# ============================================================
Say "Setup finished. Failures=$($script:Failures.Count) Warnings=$($script:Warnings.Count)" "STEP"

Write-Host ""
Write-Host "Verify in Splunk Web (Win 11, http://localhost:8000, socadmin / P@ssw0rd2026!):" -ForegroundColor Cyan
Write-Host ""
Write-Host "  # Is the Windows Server VM up?" -ForegroundColor Cyan
Write-Host "  index=main host=$TargetHostname earliest=-5m"
Write-Host "  | stats count as events"
Write-Host "  | eval status = if(events > 0, `"UP`", `"DOWN`")"
Write-Host "  | table status, events"
Write-Host ""

if ($LogFile) {
    $logFileBase = Split-Path $LogFile -Leaf
    Write-Host "  # Custom log file events" -ForegroundColor Cyan
    Write-Host "  index=$Index sourcetype=$Sourcetype host=$TargetHostname earliest=-15m"
    Write-Host "  | table _time, _raw"
    Write-Host "  | head 20"
    Write-Host ""
    Write-Host "  # Search by filename" -ForegroundColor Cyan
    Write-Host "  index=$Index source=`"*$logFileBase`" earliest=-15m"
    Write-Host ""
}

Write-Host "Logs:" -ForegroundColor Cyan
Write-Host "  $script:LogFile"
Write-Host "  $script:Transcript"
Write-Host ""

try { Stop-Transcript | Out-Null } catch { }

if ($script:Failures.Count -gt 0) { exit 2 } else { exit 0 }