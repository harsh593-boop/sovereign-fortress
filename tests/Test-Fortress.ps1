<#
Zero-leak acceptance tests.   .\tests\Test-Fortress.ps1 -Mode full|traffic
Runs as a standard user. Prints a PASS/FAIL table; exit code = number of failures.
#>
param([Parameter(Mandatory)][ValidateSet('full','traffic')][string]$Mode,
      [string]$Vps = $env:FORTRESS_HOST, [string]$NextDnsProfile = $env:FORTRESS_NEXTDNS, [string]$CampusIp = $env:FORTRESS_CAMPUS_IP)
if (-not $Vps -or ($Mode -eq 'traffic' -and -not $NextDnsProfile)) { throw 'set FORTRESS_HOST (and FORTRESS_NEXTDNS for traffic mode) or pass -Vps/-NextDnsProfile' }
$ErrorActionPreference = 'Continue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$R = [Collections.Generic.List[object]]::new()
function T($name, [scriptblock]$check) {
  try { $ok, $detail = & $check } catch { $ok = $false; $detail = $_.Exception.Message }
  $R.Add([pscustomobject]@{ Test = $name; Result = $(if ($ok) { 'PASS' } else { 'FAIL' }); Detail = "$detail" })
}
function Get-Text($u) { (Invoke-WebRequest $u -UseBasicParsing -TimeoutSec 15).Content.Trim() }

function Get-StunMapped([string]$hostName = 'stun.l.google.com', [int]$port = 19302) {
  $u = New-Object Net.Sockets.UdpClient([Net.Sockets.AddressFamily]::InterNetwork)
  $u.Client.ReceiveTimeout = 5000
  try {
    $tid = New-Object byte[] 12; (New-Object Random).NextBytes($tid)
    $req = [byte[]](0x00,0x01,0x00,0x00,0x21,0x12,0xA4,0x42) + $tid      # Binding Request, magic cookie
    $ip = ([Net.Dns]::GetHostAddresses($hostName) | Where-Object AddressFamily -eq 'InterNetwork')[0]
    $ep = New-Object Net.IPEndPoint($ip, $port)
    for ($try = 0; $try -lt 3; $try++) {
      [void]$u.Send($req, $req.Length, $ep)
      try { $res = $u.Receive([ref]$ep); break } catch { $res = $null }
    }
    if (-not $res) { throw 'no STUN response (UDP blocked)' }
    $i = 20
    while ($i + 4 -le $res.Length) {
      $type = ($res[$i] -shl 8) -bor $res[$i + 1]; $len = ($res[$i + 2] -shl 8) -bor $res[$i + 3]; $v = $i + 4
      if ($type -eq 0x0020 -or $type -eq 0x0001) {
        $a = $res[($v + 4)..($v + 7)]
        if ($type -eq 0x0020) { $a = 0..3 | ForEach-Object { $a[$_] -bxor (0x21,0x12,0xA4,0x42)[$_] } }
        return ($a -join '.')
      }
      $i = $v + $len + ((4 - $len % 4) % 4)
    }
    throw 'no mapped address in STUN response'
  } finally { $u.Close() }
}

T 'TUN adapter fortress0 Up' { $a = Get-NetAdapter -Name fortress0 -EA SilentlyContinue; ($a.Status -eq 'Up'), "$($a.Status)" }
T 'Public IPv4 (api.ipify.org)' { $ip = Get-Text 'https://api.ipify.org'; ($ip -eq $Vps), $ip }
T 'Public IPv4 (ifconfig.me)'   { $ip = Get-Text 'https://ifconfig.me/ip'; ($ip -eq $Vps), $ip }
T 'No IPv6 egress (api64.ipify)' {
  try { $ip = Get-Text 'https://api64.ipify.org' } catch { return $true, 'no IPv6 path' }
  ($ip -notmatch ':' -and $ip -eq $Vps), $ip
}
T 'WebRTC: raw UDP STUN mapped IP' { $ip = Get-StunMapped; ($ip -eq $Vps), "stun.l.google.com:19302 -> $ip" }

$nd = $null; try { $nd = Invoke-RestMethod 'https://test.nextdns.io' -TimeoutSec 15 } catch {}
if ($Mode -eq 'traffic') {
  T 'NextDNS status ok + profile' { ($nd.status -eq 'ok' -and $nd.profile -eq $NextDnsProfile), "status=$($nd.status) profile=$($nd.profile) proto=$($nd.protocol)" }
  T 'NextDNS query source not VPS' {
    $src = if ($nd.clientIP) { $nd.clientIP } else { $nd.srcIP }
    ($src -and $src -ne $Vps), "src=$src (expected campus $CampusIp)"
  }
  T 'YogaDNS running' { $p = @(Get-Process YogaDNS -EA SilentlyContinue).Count; ($p -gt 0), "$p process(es)" }
} else {
  T 'NextDNS NOT answering' { ($nd.status -ne 'ok'), "status=$($nd.status)" }
  T 'DNS answered by VPS AdGuard (ad domain sinkholed)' {
    $a = @(Resolve-DnsName doubleclick.net -Type A -DnsOnly -QuickTimeout -EA Stop | Where-Object IPAddress | ForEach-Object IPAddress)
    ($a.Count -gt 0 -and ($a | Where-Object { $_ -ne '0.0.0.0' }).Count -eq 0), "doubleclick.net -> $($a -join ',')"
  }
  T 'DNS resolves normal names' { $a = (Resolve-DnsName example.com -Type A -DnsOnly -EA Stop | Where-Object IPAddress)[0].IPAddress; [bool]$a, $a }
  T 'Kill switch rules present' { $n = @(Get-NetFirewallRule -Group SovereignFortress -EA SilentlyContinue).Count; ($n -ge 5), "$n rules" }
}

$R | Format-Table -AutoSize -Wrap
$fail = @($R | Where-Object Result -eq 'FAIL').Count
"{0}: {1}/{2} passed" -f $Mode, ($R.Count - $fail), $R.Count
exit $fail
