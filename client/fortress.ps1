<#
.SYNOPSIS  Sovereign Fortress v2 Windows controller (native sing-box TUN as a SYSTEM scheduled task).
.EXAMPLE   .\fortress.ps1 install
           .\fortress.ps1 mode full            # full tunnel, VPS DNS, kill switch on
           .\fortress.ps1 mode traffic         # tunnel TCP/UDP, DNS stays local (YogaDNS/NextDNS)
           .\fortress.ps1 mode off             # stop tunnel, remove kill switch, restore firewall
           .\fortress.ps1 killswitch on|off
           .\fortress.ps1 status
           .\fortress.ps1 uninstall
Admin actions self-elevate (UAC) and log to C:\ProgramData\SovereignFortress\last-run.log.
Configs/binary are produced by tools\gen_client.py into %LOCALAPPDATA%\SovereignFortress.
#>
param(
  [Parameter(Position = 0)][ValidateSet('install', 'mode', 'killswitch', 'status', 'uninstall')][string]$Action = 'status',
  [Parameter(Position = 1)][string]$Arg,
  [switch]$NoKillSwitch
)
$ErrorActionPreference = 'Stop'
$Data = 'C:\ProgramData\SovereignFortress'
$Src = Join-Path $env:LOCALAPPDATA 'SovereignFortress'
$Task = 'SovereignFortress'
$Group = 'SovereignFortress'
$Tun = 'fortress0'
$Exe = Join-Path $Data 'sing-box.exe'
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrator')

function Get-Status {
  $t = Get-ScheduledTask -TaskName $Task -ErrorAction SilentlyContinue
  $mode = if (Test-Path "$Data\mode.txt") { (Get-Content "$Data\mode.txt").Trim() } else { 'none' }
  $adapter = Get-NetAdapter -Name $Tun -ErrorAction SilentlyContinue
  $fw = @(Get-NetFirewallRule -Group $Group -ErrorAction SilentlyContinue).Count
  $out = (Get-NetFirewallProfile | ForEach-Object { $_.DefaultOutboundAction }) -join ','
  [pscustomobject]@{
    Installed = [bool]$t; TaskState = $t.State; Mode = $mode
    TunnelAdapter = if ($adapter) { $adapter.Status } else { 'absent' }
    KillSwitchRules = $fw; ProfileDefaultOutbound = $out
  } | Format-List
}
if ($Action -eq 'status') { Get-Status; return }

if (-not $IsAdmin) {
  $argl = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", $Action)
  if ($Arg) { $argl += $Arg }
  if ($NoKillSwitch) { $argl += '-NoKillSwitch' }
  $p = Start-Process powershell -Verb RunAs -ArgumentList $argl -Wait -PassThru
  if (Test-Path "$Data\last-run.log") { Get-Content "$Data\last-run.log" -Tail 30 }
  exit $p.ExitCode
}

New-Item -ItemType Directory -Force $Data | Out-Null
# non-secret files the unelevated user may read (config files stay admin/SYSTEM only)
foreach ($f in 'last-run.log', 'mode.txt') {
  if (-not (Test-Path "$Data\$f")) { New-Item -ItemType File "$Data\$f" | Out-Null }
  & icacls "$Data\$f" /grant 'Users:(R)' | Out-Null
}
Start-Transcript -Path "$Data\last-run.log" -Force | Out-Null
try {
  function Protect-Dir {
    & icacls $Data /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null
  }

  function Stop-Tunnel {
    Get-ScheduledTask -TaskName $Task -ErrorAction SilentlyContinue | Stop-ScheduledTask -ErrorAction SilentlyContinue
    Get-Process sing-box -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $Exe } | Stop-Process -Force
  }

  function Disable-KillSwitch {
    Get-NetFirewallRule -Group $Group -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    $st = "$Data\fw-state.json"
    if (Test-Path $st) {
      $s = Get-Content $st | ConvertFrom-Json
      foreach ($p in $s.PSObject.Properties) { Set-NetFirewallProfile -Name $p.Name -DefaultOutboundAction $p.Value }
      Remove-Item $st
    } else { Set-NetFirewallProfile -All -DefaultOutboundAction Allow }
    Write-Host 'kill switch: OFF'
  }

  function Enable-KillSwitch($mode) {
    $st = "$Data\fw-state.json"
    if (-not (Test-Path $st)) {
      $s = @{}; Get-NetFirewallProfile | ForEach-Object { $s[$_.Name] = [string]$_.DefaultOutboundAction }
      $s | ConvertTo-Json | Set-Content $st
    }
    Get-NetFirewallRule -Group $Group -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    $c = @{ Group = $Group; Direction = 'Outbound'; Action = 'Allow'; Enabled = 'True' }
    New-NetFirewallRule @c -DisplayName 'FortressAllow sing-box' -Program $Exe | Out-Null
    New-NetFirewallRule @c -DisplayName 'FortressAllow tunnel' -InterfaceAlias $Tun | Out-Null
    New-NetFirewallRule @c -DisplayName 'FortressAllow DHCP' -Protocol UDP -LocalPort 68 -RemotePort 67 | Out-Null
    # LAN/link-local/multicast, but never plain DNS (53) or DoT (853) outside the tunnel
    $lan = '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16', '224.0.0.0/4', '255.255.255.255'
    $ports = '1-52', '54-852', '854-65535'
    foreach ($proto in 'TCP', 'UDP') {
      New-NetFirewallRule @c -DisplayName "FortressAllow LAN $proto" -Protocol $proto -RemoteAddress $lan -RemotePort $ports | Out-Null
    }
    if ($mode -eq 'traffic') {
      foreach ($n in 'YogaDNS', 'ServiceManager') {
        $f = Get-ChildItem 'C:\Program Files (x86)\YogaDNS' -Filter "$n.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($f) { New-NetFirewallRule @c -DisplayName "FortressAllow $n" -Program $f.FullName | Out-Null }
      }
    }
    Set-NetFirewallProfile -All -DefaultOutboundAction Block
    Write-Host 'kill switch: ON (default outbound = Block, allow-list only)'
  }

  function Install-All {
    $bin = Join-Path $Src 'bin'
    foreach ($f in 'sing-box.exe', 'libcronet.dll') {
      if (Test-Path "$bin\$f") { Copy-Item "$bin\$f" $Data -Force }
    }
    if (-not (Test-Path $Exe)) { throw "missing $bin\sing-box.exe - run: python tools\gen_client.py" }
    Protect-Dir
    $act = New-ScheduledTaskAction -Execute $Exe -Argument "run -D `"$Data`" -c `"$Data\active.json`"" -WorkingDirectory $Data
    $trg = New-ScheduledTaskTrigger -AtStartup
    $pr = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
    $set = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) `
      -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable
    Register-ScheduledTask -TaskName $Task -Action $act -Trigger $trg -Principal $pr -Settings $set -Force | Out-Null
    Disable-ScheduledTask -TaskName $Task | Out-Null
    Write-Host 'installed (task registered, disabled until a mode is selected)'
  }

  function Set-Mode($m) {
    $map = @{ full = 'full.json'; traffic = 'traffic.json' }
    if ($m -eq 'off') {
      Stop-Tunnel; Disable-ScheduledTask -TaskName $Task | Out-Null
      Disable-KillSwitch; Set-Content "$Data\mode.txt" 'off'; return
    }
    if (-not $map.ContainsKey($m)) { throw "mode must be full|traffic|off" }
    if (-not (Test-Path (Join-Path $Src $map[$m]))) { throw "missing config; run tools\gen_client.py" }
    Install-All
    # warp-svc and a leftover tunnel would fight over routes
    Get-Process warp-svc -ErrorAction SilentlyContinue | ForEach-Object { & warp-cli disconnect 2>$null | Out-Null }
    Stop-Tunnel
    Copy-Item (Join-Path $Src $map[$m]) "$Data\active.json" -Force
    & $Exe check -c "$Data\active.json"
    if ($LASTEXITCODE) { throw 'config validation failed; tunnel not started' }
    Set-Content "$Data\mode.txt" $m
    Disable-KillSwitch   # clean slate: no stale rules between modes
    Enable-ScheduledTask -TaskName $Task | Out-Null
    Start-ScheduledTask -TaskName $Task
    $ok = $false
    for ($i = 0; $i -lt 20; $i++) {
      Start-Sleep 1
      $a = Get-NetAdapter -Name $Tun -ErrorAction SilentlyContinue
      if ($a -and $a.Status -eq 'Up') { $ok = $true; break }
    }
    if (-not $ok) { Stop-Tunnel; throw 'tunnel adapter did not come up' }
    $useKs = (-not $NoKillSwitch) -and ($m -eq 'full')
    if ($Arg -eq 'ks') { $useKs = $true }
    if ($useKs) { Enable-KillSwitch $m }
    Write-Host "mode: $m active"
  }

  switch ($Action) {
    'install' { Install-All }
    'mode' { Set-Mode $Arg.ToLower() }
    'killswitch' {
      if ($Arg -eq 'on') { Enable-KillSwitch ((Get-Content "$Data\mode.txt" -ErrorAction SilentlyContinue)) } else { Disable-KillSwitch }
    }
    'uninstall' {
      Stop-Tunnel; Disable-KillSwitch
      Unregister-ScheduledTask -TaskName $Task -Confirm:$false -ErrorAction SilentlyContinue
      Remove-Item $Data -Recurse -Force -ErrorAction SilentlyContinue
      Write-Host 'uninstalled'
    }
  }
} catch {
  Write-Host "ERROR: $($_.Exception.Message)"
  Stop-Transcript | Out-Null
  exit 1
}
Stop-Transcript | Out-Null
