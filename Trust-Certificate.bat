@echo off
setlocal DisableDelayedExpansion
cd /d "%~dp0" || exit /b 1
echo ======================================================================
echo Sovereign Fortress - Verify and Trust a Private Root CA
echo ======================================================================
echo.
echo WARNING: A trusted root can issue certificates for ANY website.
echo Trust only a CA you control and whose administrator you trust.
echo Obtain the SHA256 certificate fingerprint over an INDEPENDENT trusted channel.
echo Do not use a fingerprint supplied only with this downloaded folder.
echo No certificate will be imported without fingerprint matching and confirmation.
echo.
powershell.exe -NoProfile -Command "$ErrorActionPreference = 'Stop'; try { $clientRoot = $env:FORTRESS_CLIENT_HOME; if ([string]::IsNullOrWhiteSpace($clientRoot)) { $clientRoot = Join-Path $env:LOCALAPPDATA 'SovereignFortress' }; $caPath = Join-Path $clientRoot 'ca.crt'; $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2((Resolve-Path -LiteralPath $caPath).Path); $bc = $cert.Extensions | Where-Object { $_.Oid.Value -eq ('2.5.29.' + '19') }; if (!$bc -or !$bc.CertificateAuthority -or $cert.Subject -ne $cert.Issuer) { throw 'Certificate is not a self-issued CA root' }; if ((Get-Date) -lt $cert.NotBefore -or (Get-Date) -gt $cert.NotAfter) { throw 'Certificate is outside its validity period' }; $sha = [System.Security.Cryptography.SHA256]::Create(); try { $fingerprint = [BitConverter]::ToString($sha.ComputeHash($cert.RawData)).Replace('-', '') } finally { $sha.Dispose() }; Write-Host ('Subject: ' + $cert.Subject); Write-Host ('Issuer: ' + $cert.Issuer); Write-Host ('Expires: ' + $cert.NotAfter); Write-Host ('Certificate SHA256: ' + $fingerprint); $expected = (Read-Host 'Enter independently obtained SHA256 certificate fingerprint').Replace(':', '').Replace(' ', '').ToUpperInvariant(); if ($expected -notmatch '^[0-9A-F]{64}$' -or $expected -cne $fingerprint) { throw 'Fingerprint mismatch; nothing imported' }; if ((Read-Host 'Type TRUST to allow this CA to authenticate ANY website for your Windows user') -cne 'TRUST') { throw 'Cancelled; nothing imported' }; $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'CurrentUser'); try { $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite); $store.Add($cert) } finally { $store.Close() }; Write-Host '[SUCCESS] Verified certificate added to CurrentUser Root. Individual apps may use separate trust stores.'; exit 0 } catch { Write-Host ('[FAILED] ' + $_.Exception.Message); exit 1 }"
set "RESULT=%ERRORLEVEL%"
echo.
pause
exit /b %RESULT%
