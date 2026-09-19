@echo off
title Sovereign Fortress - WireGuard over TCP (wstunnel)
cd /d "%~dp0"

echo ======================================================================
echo    SOVEREIGN FORTRESS: WireGuard-over-TCP (wstunnel Forwarder)
echo ======================================================================
echo.

set "SERVER_IP=<YOUR_SERVER_IP>"
if exist fortress_config.json (
    for /f "tokens=2 delims=:," %%a in ('findstr /i "server_ip" fortress_config.json') do (
        set "SERVER_IP=%%~a"
    )
)
:: Trim whitespace/quotes
set "SERVER_IP=%SERVER_IP: =%"
set "SERVER_IP=%SERVER_IP:"=%"

if not exist wstunnel.exe (
    echo [*] Downloading wstunnel v10.7.1 for Windows 64-bit...
    powershell -Command "$expected = '830e071e6beea25dfae2cb52eb71bb95ecfe29b2e88220025fae8fb85579f1fa'; Invoke-WebRequest -Uri 'https://github.com/erebe/wstunnel/releases/download/v10.7.1/wstunnel_10.7.1_windows_amd64.zip' -OutFile 'wstunnel.zip'; $hash = (Get-FileHash 'wstunnel.zip' -Algorithm SHA256).Hash.ToLower(); if ($hash -ne $expected) { Write-Error 'SHA256 verification failed!'; Remove-Item 'wstunnel.zip'; exit 1 }; Expand-Archive -Path 'wstunnel.zip' -DestinationPath '.' -Force; Remove-Item 'wstunnel.zip'"
    if not exist wstunnel.exe (
        echo [-] Download or verification failed. Please download wstunnel.exe manually from:
        echo     https://github.com/erebe/wstunnel/releases
        pause
        exit /b 1
    )
    echo [+] wstunnel.exe verified and installed successfully.
)

echo [*] Starting wstunnel TCP forwarder...
echo [*] Local UDP: 127.0.0.1:51820 -^> Remote TCP: wss://%SERVER_IP%:8080 (Camouflage: gateway.icloud.com)
echo [*] Activate WireGuard using profile: fortress-wireguard-tcp.conf
echo.
echo Press Ctrl+C to stop the tunnel.
echo.

wstunnel.exe client -L udp://127.0.0.1:51820:127.0.0.1:51820 --tls-sni gateway.icloud.com --tls-verify-certificate false wss://%SERVER_IP%:8080

pause
