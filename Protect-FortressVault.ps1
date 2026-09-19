# Sovereign Fortress — Windows DPAPI Client Key & Config Vault
# Cryptographically protects keys and configs at rest using Windows DPAPI
param (
    [Parameter(Mandatory=$true)]
    [ValidateSet("Lock", "Unlock")]
    [string]$Action,
    [string[]]$AdditionalFiles = @()
)

Add-Type -AssemblyName System.Security

# Discover sensitive files dynamically in current script folder and user profile
$ScriptDir = $PSScriptRoot
if (-not $ScriptDir) { $ScriptDir = Get-Location }

$DefaultCandidates = @(
    (Join-Path $ScriptDir "fortress-wireguard.conf"),
    (Join-Path $ScriptDir "fortress-wireguard-tcp.conf"),
    (Join-Path $ScriptDir "client_profiles.txt"),
    (Join-Path $ScriptDir "fortress_config.json"),
    (Join-Path $ScriptDir "fortress-full-tunnel.json"),
    (Join-Path $ScriptDir "fortress-traffic-only.json")
)

# Search for SSH keys matching standard patterns in Downloads or script dir
$SshKeyDownloads = Get-ChildItem -Path "$env:USERPROFILE\Downloads" -Filter "ssh-key-*.key" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
if ($SshKeyDownloads) {
    $DefaultCandidates += $SshKeyDownloads
}

$TargetFiles = @($DefaultCandidates + $AdditionalFiles) | Select-Object -Unique

function Secure-ZeroFile($filePath) {
    if (Test-Path $filePath) {
        $len = (Get-Item $filePath).Length
        if ($len -gt 0) {
            $bytes = New-Object byte[] $len
            (New-Object System.Random).NextBytes($bytes)
            [System.IO.File]::WriteAllBytes($filePath, $bytes)
            $zeros = New-Object byte[] $len
            [System.IO.File]::WriteAllBytes($filePath, $zeros)
        }
        Remove-Item -Path $filePath -Force
    }
}

if ($Action -eq "Lock") {
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "   LOCKING SOVEREIGN FORTRESS VAULT (WINDOWS DPAPI)       " -ForegroundColor Yellow
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "[*] Encrypting sensitive configuration files and private keys at rest..." -ForegroundColor Gray

    $lockedCount = 0
    foreach ($file in $TargetFiles) {
        if (Test-Path $file) {
            $rawBytes = [System.IO.File]::ReadAllBytes($file)
            $encryptedBytes = [System.Security.Cryptography.ProtectedData]::Protect(
                $rawBytes,
                $null,
                [System.Security.Cryptography.DataProtectionScope]::CurrentUser
            )
            $encPath = "$file.enc"
            [System.IO.File]::WriteAllBytes($encPath, $encryptedBytes)
            Secure-ZeroFile $file
            Write-Host " [+] Encrypted and zeroed: $(Split-Path $file -Leaf) -> $(Split-Path $encPath -Leaf)" -ForegroundColor Green
            $lockedCount++
        } elseif (Test-Path "$file.enc") {
            Write-Host " [=] Already locked: $(Split-Path $file -Leaf).enc" -ForegroundColor DarkGray
        }
    }
    Write-Host "`n[✓] Vault Locked! $lockedCount file(s) encrypted with Windows DPAPI (tied to your Windows login)." -ForegroundColor Green
}
elseif ($Action -eq "Unlock") {
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "   UNLOCKING SOVEREIGN FORTRESS VAULT (WINDOWS DPAPI)     " -ForegroundColor Yellow
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "[*] Decrypting sensitive configuration files for active session..." -ForegroundColor Gray

    $unlockedCount = 0
    foreach ($file in $TargetFiles) {
        $encPath = "$file.enc"
        if (Test-Path $encPath) {
            $encBytes = [System.IO.File]::ReadAllBytes($encPath)
            try {
                $decryptedBytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
                    $encBytes,
                    $null,
                    [System.Security.Cryptography.DataProtectionScope]::CurrentUser
                )
                [System.IO.File]::WriteAllBytes($file, $decryptedBytes)
                Remove-Item -Path $encPath -Force
                Write-Host " [+] Decrypted and restored: $(Split-Path $file -Leaf)" -ForegroundColor Green
                $unlockedCount++
            } catch {
                Write-Host " [-] Failed to decrypt $encPath : $($_.Exception.Message)" -ForegroundColor Red
            }
        } elseif (Test-Path $file) {
            Write-Host " [=] Already unlocked: $(Split-Path $file -Leaf)" -ForegroundColor DarkGray
        }
    }
    Write-Host "`n[✓] Vault Unlocked! $unlockedCount file(s) restored and ready for use." -ForegroundColor Green
}
