<#
 Leak/acceptance tests. Usage: .\tests\Test-Fortress.ps1 -Mode full|traffic   (runs unelevated)
 Prints PASS/FAIL/SKIP per check; never claims a pass for a skipped check.
#>
param([Parameter(Mandatory)][ValidateSet('full', 'traffic')][string]$Mode, [string]$VpsIp = '144.24.112.45')
$ErrorActionPreference = 'Continue'
$res = @()
function Rec($n, $s, $d) { $script:res += [pscustomobject]@{ Test = $n; Result = $s; Detail = $d } }
function Curl($u) { (& curl.exe -s --ssl-no-revoke -m 15 $u) }

$ad = Get-NetAdapter -Name fortress0 -ErrorAction SilentlyContinue
Rec 'tun adapter up' ($(if ($ad -and $ad.Status -eq 'Up') { 'PASS' } else { 'FAIL' })) ''
$ip = Curl 'https://api.ipify.org'
Rec 'public IPv4 == VPS' ($(if ($ip -eq $VpsIp) { 'PASS' } else { 'FAIL' })) "got $ip"
$ip2 = Curl 'https://ifconfig.me/ip'
Rec 'public IPv4 (2nd service)' ($(if ($ip2 -eq $VpsIp) { 'PASS' } else { 'FAIL' })) "got $ip2"
$v6 = Curl 'https://api64.ipify.org'
Rec 'IPv6 not exposed' ($(if ($v6 -eq $VpsIp -or -not $v6 -or $v6 -notmatch ':') { 'PASS' } else { 'FAIL' })) "api64 -> $v6"
# STUN: binding request over UDP must show the VPS address
$stun = python -c @"
import socket,os,struct
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(5)
tid=os.urandom(12);s.sendto(struct.pack('>HHI',1,0,0x2112A442)+tid,('stun.l.google.com',19302))
d=s.recv(512);i=20
while i<len(d):
    t,l=struct.unpack('>HH',d[i:i+4])
    if t==0x20:
        x=d[i+8:i+12];print('.'.join(str(b^m) for b,m in zip(x,[0x21,0x12,0xA4,0x42])));break
    i+=4+l+(-l%4)
"@ 2>&1
Rec 'STUN reflexive address == VPS' ($(if ("$stun".Trim() -eq $VpsIp) { 'PASS' } else { 'FAIL' })) "stun -> $stun"
$nd = Curl 'https://test.nextdns.io'
if ($Mode -eq 'traffic') {
  $ok = $nd -match '"status"\s*:\s*"ok"' -and $nd -match '68f58b'
  Rec 'NextDNS profile 68f58b' ($(if ($ok) { 'PASS' } else { 'FAIL' })) ($nd -replace '\s+', ' ')
} else {
  Rec 'DNS answered by VPS AGH (not NextDNS/campus)' ($(if ($nd -notmatch '68f58b') { 'PASS' } else { 'FAIL' })) ($nd -replace '\s+', ' ')
}
# plain DNS to an arbitrary resolver must not reveal campus path
$ns = (nslookup -type=TXT o-o.myaddr.l.google.com 8.8.8.8 2>&1 | Select-String 'text =' | Out-String).Trim()
Rec 'direct DNS to 8.8.8.8 egress' 'INFO' "resolver seen by Google: $ns"
$gw = (Get-NetRoute -DestinationPrefix 0.0.0.0/1 -ErrorAction SilentlyContinue | Select-Object -First 1).InterfaceAlias
Rec 'default route via tun' ($(if ($gw -eq 'fortress0') { 'PASS' } else { 'FAIL' })) "0.0.0.0/1 -> $gw"
$res | Format-Table -AutoSize -Wrap | Out-String -Width 250
if ($res | Where-Object Result -eq 'FAIL') { exit 1 }
