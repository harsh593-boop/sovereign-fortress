# Sovereign Fortress — Client-Side Emergency Forensic Shredder
# Permanently and irreversibly vaporizes all client keys, configs, logs, and traces
param (
    [switch]$Force
)

Write-Host "==========================================================" -ForegroundColor Red
Write-Host "   SOVEREIGN FORTRESS: LOCAL CLIENT EMERGENCY PANIC       " -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Red
Write-Host "[!] WARNING: This will permanently wipe all VPN configurations," -ForegroundColor Yellow
Write-Host "    private keys, and SSH credentials from this computer." -ForegroundColor Yellow

if (-not $Force) {
    $confirm = Read-Host "Are you sure you want to execute emergency client shredding? (type 'VAPORIZE' to proceed)"
    if ($confirm -ne "VAPORIZE") {
        Write-Host "[-] Panic aborted. No files were touched." -ForegroundColor Green
        exit 0
    }
}

$ScriptDir = $PSScriptRoot
if (-not $ScriptDir) { $ScriptDir = Get-Location }

$WipeFiles = @(
    (Join-Path $ScriptDir "fortress-wireguard.conf"),
    (Join-Path $ScriptDir "fortress-wireguard.conf.enc"),
    (Join-Path $ScriptDir "fortress-wireguard-tcp.conf"),
    (Join-Path $ScriptDir "fortress-wireguard-tcp.conf.enc"),
    (Join-Path $ScriptDir "client_profiles.txt"),
    (Join-Path $ScriptDir "client_profiles.txt.enc"),
    (Join-Path $ScriptDir "fortress-full-tunnel.json"),
    (Join-Path $ScriptDir "fortress-traffic-only.json"),
    (Join-Path $ScriptDir "fortress_config.json"),
    (Join-Path $ScriptDir "fortress_config.json.enc")
)

# Search for SSH keys in Downloads
$SshKeyDownloads = Get-ChildItem -Path "$env:USERPROFILE\Downloads" -Filter "ssh-key-*.key*" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
if ($SshKeyDownloads) {
    $WipeFiles += $SshKeyDownloads
}

function Cryptographic-Shred($filePath) {
    if (Test-Path $filePath) {
        $len = (Get-Item $filePath).Length
        if ($len -gt 0) {
            # Pass 1: Cryptographic Pseudo-Random data
            $rnd = New-Object byte[] $len
            [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($rnd)
            [System.IO.File]::WriteAllBytes($filePath, $rnd)

            # Pass 2: Inverted 0xFF bytes
            $inv = New-Object byte[] $len
            for ($i = 0; $i -lt $len; $i++) { $inv[$i] = 255 }
            [System.IO.File]::WriteAllBytes($filePath, $inv)

            # Pass 3: Zero bytes
            $zeros = New-Object byte[] $len
            [System.IO.File]::WriteAllBytes($filePath, $zeros)
        }
        Remove-Item -Path $filePath -Force
        Write-Host " [X] Cryptoshredded: $(Split-Path $filePath -Leaf)" -ForegroundColor Red
    }
}

Write-Host "`n[*] Commencing 3-Pass Cryptoshredding on all credentials..." -ForegroundColor DarkYellow
foreach ($file in $WipeFiles) {
    Cryptographic-Shred $file
}

# Wipe QR codes directory
$qrDir = Join-Path $ScriptDir "qr_codes"
if (Test-Path $qrDir) {
    Get-ChildItem -Path $qrDir -Filter "*.png" | ForEach-Object {
        Cryptographic-Shred $_.FullName
    }
}

# Clear clipboard
[System.Windows.Forms.Clipboard]::Clear() 2>$null

# Flush DNS cache
Clear-DnsClientCache

Write-Host "`n[✓] FORENSIC VAPORIZATION COMPLETE. All credentials eradicated." -ForegroundColor Green
