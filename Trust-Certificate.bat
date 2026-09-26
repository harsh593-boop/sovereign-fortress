@echo off
setlocal
cd /d "%~dp0"
echo ======================================================================
echo Sovereign Fortress — Install Trusted Root CA Certificate
echo ======================================================================
echo.
echo Installing ca.crt into Windows CurrentUser Trusted Root Store...
echo A Windows Security Warning dialog will appear asking for confirmation.
echo Please click [Yes] to trust the Sovereign Fortress Root CA.
echo.
powershell -NoProfile -ExecutionPolicy Bypass -Command "Import-Certificate -FilePath '%~dp0ca.crt' -CertStoreLocation Cert:\CurrentUser\Root"
echo.
if %ERRORLEVEL% EQU 0 (
    echo [SUCCESS] Sovereign Fortress Root CA is now installed and trusted!
    echo HTTPS subscription links and the Web Portal will now be 100%% trusted by Windows and Hiddify.
) else (
    echo [!] Installation was cancelled or failed.
)
echo.
pause
