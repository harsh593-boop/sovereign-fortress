@echo off
setlocal DisableDelayedExpansion
title Sovereign Fortress - WireGuard over TCP (wstunnel)
cd /d "%~dp0" || exit /b 1
echo ======================================================================
echo    SOVEREIGN FORTRESS: WireGuard-over-TCP (wstunnel Forwarder)
echo ======================================================================
echo.
echo Uses the configured domain, falling back to server_ip.
echo TLS verifies that endpoint; its certificate must contain the matching SAN.
echo Do not disable certificate verification to work around a name mismatch.
echo Activate WireGuard using profile: fortress-wireguard-tcp.conf
echo Local UDP: 127.0.0.1:51820 - Remote TCP: configured endpoint on port 8080
echo Press Ctrl+C to stop the tunnel.
echo.
rem Parse JSON and pass arguments inside PowerShell, never interpolate config into cmd.exe.
powershell.exe -NoProfile -Command "$ErrorActionPreference = 'Stop'; try { $clientRoot = $env:FORTRESS_CLIENT_HOME; if ([string]::IsNullOrWhiteSpace($clientRoot)) { $clientRoot = Join-Path $env:LOCALAPPDATA 'SovereignFortress' }; $cfgPath = $env:FORTRESS_CLIENT_CONFIG; if ([string]::IsNullOrWhiteSpace($cfgPath)) { $cfgPath = Join-Path $clientRoot 'fortress_config.json' }; $tools = Join-Path $clientRoot 'tools'; New-Item -ItemType Directory -Path $tools -Force | Out-Null; $binary = Join-Path $tools 'wstunnel.exe'; $archive = Join-Path $tools 'wstunnel.zip'; $cfg = Get-Content -LiteralPath $cfgPath -Raw | ConvertFrom-Json -ErrorAction Stop; $server = [string]$cfg.domain; if ([string]::IsNullOrWhiteSpace($server) -or $server.StartsWith('<')) { $server = [string]$cfg.server_ip }; $server = $server.Trim(); if ([string]::IsNullOrWhiteSpace($server) -or [Uri]::CheckHostName($server) -eq [UriHostNameType]::Unknown) { throw 'Configure a valid domain or server_ip first' }; $uriHost = $server; if ($server.Contains(':') -and !$server.StartsWith('[')) { $uriHost = '[' + $server + ']' }; if (!(Test-Path -LiteralPath $binary -PathType Leaf)) { Write-Host '[*] Downloading pinned wstunnel v10.7.1 for Windows 64-bit...'; $expected = '830e071e6beea25dfae2cb52eb71bb95ecfe29b2e88220025fae8fb85579f1fa'; Invoke-WebRequest -Uri 'https://github.com/erebe/wstunnel/releases/download/v10.7.1/wstunnel_10.7.1_windows_amd64.zip' -OutFile $archive; $hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant(); if ($hash -cne $expected) { Remove-Item -LiteralPath $archive; throw 'SHA256 verification failed' }; Expand-Archive -LiteralPath $archive -DestinationPath $tools -Force; Remove-Item -LiteralPath $archive }; if (!(Test-Path -LiteralPath $binary -PathType Leaf)) { throw 'wstunnel.exe was not found in the verified archive' }; $endpoint = 'wss://' + $uriHost + ':8080'; Write-Host ('[*] Attempting certificate-verified TLS connection to ' + $endpoint); & $binary client --tls-verify-certificate -L 'udp://127.0.0.1:51820:127.0.0.1:51820' $endpoint; exit $LASTEXITCODE } catch { Write-Host '[FAILED] Check configuration, download integrity, executable availability, and TLS trust. No private configuration content is displayed.'; exit 1 }"
set "RESULT=%ERRORLEVEL%"
echo.
pause
exit /b %RESULT%
