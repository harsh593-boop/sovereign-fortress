<#
Sovereign Fortress Windows client (sing-box Wintun TUN "fortress0").
  fortress.ps1 install [-Stage <dir with sing-box.exe, libcronet.dll, client.json>]   one-time, UAC once
  fortress.ps1 full       Mode A: all TCP/UDP + DNS via VPS (AdGuard Home), firewall kill switch
  fortress.ps1 traffic    Mode B: all TCP/UDP via VPS, DNS stays local (YogaDNS -> NextDNS)
  fortress.ps1 off        Tunnel down, kill switch removed, YogaDNS/WARP restored
  fortress.ps1 status | uninstall
After install, full/traffic/off run as a standard user: they trigger SYSTEM scheduled tasks (no UAC).
#>
param(
  [Parameter(Mandatory, Position = 0)][ValidateSet('install','full','traffic','off','resume','status','uninstall')][string]$Action,
  [string]$Stage = "$env:LOCALAPPDATA\SovereignFortress\bin",
  [switch]$Service
)
$ErrorActionPreference = 'Stop'
$App    = 'C:\Program Files\SovereignFortress'
$Data   = 'C:\ProgramData\SovereignFortress'
$Pub    = "$Data\pub"                       # world-readable: mode, logs
$Exe    = "$App\sing-box.exe"
$TPath  = '\SovereignFortress\'
$FwGrp  = 'SovereignFortress'
$Yoga   = 'C:\Program Files (x86)\YogaDNS\YogaDNS.exe'
$Warp   = 'C:\Program Files\Cloudflare\Cloudflare WARP\warp-cli.exe'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrator')

function Get-Mode { (Get-Content "$Pub\mode.txt" -EA SilentlyContinue) -join '' }

if ($Action -eq 'status') {
  "mode      : $(Get-Mode)"
  "core task : $((Get-ScheduledTask -TaskPath $TPath -TaskName core -EA SilentlyContinue).State)"
  "sing-box  : $(@(Get-Process sing-box -EA SilentlyContinue).Count) process(es)"
  "adapter   : $((Get-NetAdapter -Name fortress0 -EA SilentlyContinue).Status)"
  "killswitch: $(@(Get-NetFirewallRule -Group $FwGrp -EA SilentlyContinue).Count) rule(s)"
  "yogadns   : $(@(Get-Process YogaDNS -EA SilentlyContinue).Count) process(es)"
  return
}

# ---- user-facing path: trigger the SYSTEM task, then show its log ----
if (-not $Service -and $Action -in 'full','traffic','off') {
  if (-not (Get-ScheduledTask -TaskPath $TPath -TaskName $Action -EA SilentlyContinue)) { throw 'not installed: run  fortress.ps1 install  first' }
  $since = Get-Date
  Start-ScheduledTask -TaskPath $TPath -TaskName $Action
  Start-Sleep 2
  for ($i = 0; $i -lt 120 -and (Get-ScheduledTask -TaskPath $TPath -TaskName $Action).State -eq 'Running'; $i++) { Start-Sleep 1 }
  Get-Content "$Pub\last.log" -EA SilentlyContinue | Where-Object { $_ -match '^(mode=|WARNING|ERROR|\[)' }
  if ((Get-Mode) -ne $Action) { throw "switch to $Action failed (see $Pub\last.log)" }
  return
}

if (-not $isAdmin) {
  if ($Action -notin 'install','uninstall') { throw "$Action is internal (SYSTEM task only)" }
  $a = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"",$Action,'-Stage',"`"$Stage`"")
  Start-Process powershell -Verb RunAs -Wait -ArgumentList $a
  Get-Content "$Pub\install.log" -EA SilentlyContinue | Select-Object -Last 15
  return
}

# ================= privileged section (admin / SYSTEM) =================
function Lock-Acl($p) { icacls $p /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null }

function Render([string]$mode) {
  $s = Get-Content "$Data\client.json" -Raw | ConvertFrom-Json
  $t = Get-Content "$App\$mode.template.json" -Raw
  $map = @{ '@LOG@' = ("$Pub\sing-box.log" -replace '\\', '\\'); '@VPS_IP@' = $s.vps_ip; '@UUID@' = $s.uuid
            '@SNI@' = $s.sni; '@REALITY_PUBLIC@' = $s.reality_public; '@SHORT_ID@' = $s.short_id }
  foreach ($k in $map.Keys) { $t = $t.Replace($k, $map[$k]) }
  $out = "$Data\$mode.json"
  [IO.File]::WriteAllText($out, $t)
  & $Exe check -c $out
  if ($LASTEXITCODE -ne 0) { throw "sing-box config check failed for $mode (nothing changed)" }
  $out
}

function Stop-Core {
  Stop-ScheduledTask -TaskPath $TPath -TaskName core -EA SilentlyContinue
  Get-Process sing-box -EA SilentlyContinue | Stop-Process -Force
  for ($i = 0; $i -lt 15 -and (Get-NetAdapter -Name fortress0 -EA SilentlyContinue); $i++) { Start-Sleep 1 }
}

function Start-Core([string]$cfg) {
  Copy-Item $cfg "$Data\active.json" -Force
  Start-ScheduledTask -TaskPath $TPath -TaskName core
  for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep 1
    $a = Get-NetAdapter -Name fortress0 -EA SilentlyContinue
    if ($a -and $a.Status -eq 'Up' -and (Get-Process sing-box -EA SilentlyContinue)) { Start-Sleep 2; return $true }
  }
  $false
}

# Kill switch: block every outbound packet whose local address is not loopback/TUN,
# except TCP to VPS:443 (the tunnel itself) and DHCP. Interface-agnostic, so new adapters are covered.
function Set-KillSwitch([bool]$on, [string]$vps) {
  Get-NetFirewallRule -Group $FwGrp -EA SilentlyContinue | Remove-NetFirewallRule
  if (-not $on) { return }
  $ip = [Net.IPAddress]::Parse($vps).GetAddressBytes(); [Array]::Reverse($ip); $n = [BitConverter]::ToUInt32($ip, 0)
  $fmt = { param($v) $b = [BitConverter]::GetBytes([uint32]$v); [Array]::Reverse($b); ([Net.IPAddress]$b).ToString() }
  $notVps = @("0.0.0.0-$(& $fmt ($n - 1))", "$(& $fmt ($n + 1))-255.255.255.255")
  $notLocal = @('0.0.0.0-126.255.255.255', '128.0.0.0-172.18.255.255', '172.19.0.4-255.255.255.255')
  $c = @{ Group = $FwGrp; Direction = 'Outbound'; Action = 'Block'; Profile = 'Any'; Enabled = 'True' }
  New-NetFirewallRule @c -DisplayName 'SF block tcp non-VPS'     -Protocol TCP -LocalAddress $notLocal -RemoteAddress $notVps | Out-Null
  New-NetFirewallRule @c -DisplayName 'SF block tcp VPS non-443' -Protocol TCP -LocalAddress $notLocal -RemoteAddress $vps -RemotePort '1-442','444-65535' | Out-Null
  New-NetFirewallRule @c -DisplayName 'SF block udp except DHCP' -Protocol UDP -LocalAddress $notLocal -RemotePort '1-66','68-65535' | Out-Null
  New-NetFirewallRule @c -DisplayName 'SF block icmpv4'          -Protocol ICMPv4 -LocalAddress $notLocal | Out-Null
  New-NetFirewallRule @c -DisplayName 'SF block ipv6'            -RemoteAddress '::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff' | Out-Null
}

function Set-Yoga([bool]$on) {
  if ($on) {
    if (-not (Get-Process YogaDNS -EA SilentlyContinue)) { Start-ScheduledTask -TaskPath $TPath -TaskName yogadns -EA SilentlyContinue; Start-Sleep 4 }
  } else { Get-Process YogaDNS, ServiceManager -EA SilentlyContinue | Stop-Process -Force }
}

function Set-Warp([bool]$on) {
  if (-not (Test-Path $Warp)) { return }
  if ($on) { if (Test-Path "$Data\warp.was-on") { & $Warp connect | Out-Null; Remove-Item "$Data\warp.was-on" } }
  else {
    if ((& $Warp status) -match 'Connected') { New-Item "$Data\warp.was-on" -Force | Out-Null; & $Warp disconnect | Out-Null; Start-Sleep 2 }
  }
}

function Set-Mode([string]$mode) {
  if ($mode -eq 'off') {
    Stop-Core; Set-KillSwitch $false; Set-Yoga $true; Set-Warp $true
    Set-Content "$Pub\mode.txt" 'off'; Write-Host 'mode=off'; return
  }
  $cfg = Render $mode                     # validated before anything is touched
  $vps = (Get-Content "$Data\client.json" -Raw | ConvertFrom-Json).vps_ip
  Stop-Core; Set-KillSwitch $false; Set-Warp $false
  if ($mode -eq 'full') { Set-Yoga $false; Set-KillSwitch $true $vps } else { Set-Yoga $true }
  if (-not (Start-Core $cfg)) {
    Write-Warning 'tunnel did not come up; rolling back to off'
    Get-Content "$Pub\sing-box.log" -Tail 15 -EA SilentlyContinue
    Set-Mode 'off'; throw "mode $mode failed"
  }
  Set-Content "$Pub\mode.txt" $mode
  Write-Host "mode=$mode active"
}

function Register-Tasks {
  Get-ScheduledTask -TaskPath $TPath -EA SilentlyContinue | Unregister-ScheduledTask -Confirm:$false
  Get-ScheduledTask -TaskName 'SovereignFortress' -EA SilentlyContinue | Unregister-ScheduledTask -Confirm:$false  # legacy
  $sys = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  $ps  = { param($m) New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$App\fortress.ps1`" $m -Service" }
  $set = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -MultipleInstances IgnoreNew

  $coreSet = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) `
             -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
  $core = New-ScheduledTaskAction -Execute $Exe -Argument "run -D `"$Data`" -c `"$Data\active.json`"" -WorkingDirectory $App
  Register-ScheduledTask -TaskPath $TPath -TaskName core -Action $core -Principal $sys -Settings $coreSet | Out-Null
  foreach ($m in 'full','traffic','off') { Register-ScheduledTask -TaskPath $TPath -TaskName $m -Action (& $ps $m) -Principal $sys -Settings $set | Out-Null }
  $trg = @((New-ScheduledTaskTrigger -AtStartup), (New-ScheduledTaskTrigger -AtLogOn))
  $trg[1].Delay = 'PT45S'                 # re-assert after YogaDNS/WARP autostart at logon
  Register-ScheduledTask -TaskPath $TPath -TaskName resume -Action (& $ps 'resume') -Principal $sys -Settings $set -Trigger $trg | Out-Null
  # YogaDNS must run elevated in the interactive user's session, not as SYSTEM in session 0.
  $user = (Get-CimInstance Win32_ComputerSystem).UserName
  $up = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
  Register-ScheduledTask -TaskPath $TPath -TaskName yogadns -Action (New-ScheduledTaskAction -Execute $Yoga -Argument '/AutoRun') -Principal $up -Settings $set | Out-Null

  # Let any authenticated user read + run the three mode tasks (no UAC for switching).
  $svc = New-Object -ComObject Schedule.Service; $svc.Connect()
  foreach ($m in 'full','traffic','off') {
    $t = $svc.GetFolder($TPath.TrimEnd('\')).GetTask($m)
    $t.SetSecurityDescriptor($t.GetSecurityDescriptor(4) + '(A;;FRFX;;;AU)', 0)
  }
}

switch ($Action) {
  'install' {
    New-Item -ItemType Directory -Force $App, $Data, $Pub | Out-Null
    Start-Transcript "$Pub\install.log" -Force | Out-Null
    try {
      foreach ($f in 'sing-box.exe','libcronet.dll','client.json') { if (-not (Test-Path "$Stage\$f")) { throw "missing $Stage\$f" } }
      Get-Process sing-box -EA SilentlyContinue | Stop-Process -Force
      Get-NetFirewallRule -Group $FwGrp -EA SilentlyContinue | Remove-NetFirewallRule
      Get-ChildItem $Data -File | Remove-Item -Force          # legacy configs/secrets
      Copy-Item "$Stage\sing-box.exe", "$Stage\libcronet.dll" $App -Force
      Copy-Item $PSCommandPath, "$PSScriptRoot\full.template.json", "$PSScriptRoot\traffic.template.json" $App -Force
      Copy-Item "$Stage\client.json" "$Data\client.json" -Force
      Lock-Acl $Data
      icacls $Pub /grant 'Users:(OI)(CI)RX' | Out-Null
      Render 'full' | Out-Null; Render 'traffic' | Out-Null
      Register-Tasks
      Set-Content "$Pub\mode.txt" 'off'
      & $Exe version | Select-Object -First 1
      Write-Host 'installed (mode=off)'
    } finally { Stop-Transcript | Out-Null }
  }
  'uninstall' {
    Set-Mode 'off'
    Get-ScheduledTask -TaskPath $TPath -EA SilentlyContinue | Unregister-ScheduledTask -Confirm:$false
    Remove-Item $App, $Data -Recurse -Force -EA SilentlyContinue
    Write-Host 'uninstalled'
  }
  default {
    # SYSTEM task path: full | traffic | off | resume
    Start-Transcript "$Pub\last.log" -Force | Out-Null
    try {
      $m = if ($Action -eq 'resume') { Get-Mode } else { $Action }
      if ($m -notin 'full','traffic') { $m = 'off' }
      Set-Mode $m
    } finally { Stop-Transcript | Out-Null }
  }
}
