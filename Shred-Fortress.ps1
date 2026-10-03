# Best-effort removal only. No guarantee for SSD blocks, memory, or backups.
param ([switch]$Force)
$ErrorActionPreference = "Stop"
Write-Host "Removes only private Fortress files and explicitly selected keys."
Write-Host "Does not enumerate Downloads, remove unrelated keys, or change DNS."
try {
    $python = Get-Command python.exe -ErrorAction Stop
    $vault = Join-Path $PSScriptRoot "fortress_vault.py"
    if ($Force) {
        "VAPORIZE" | & $python.Source -B $vault shred
    } else {
        & $python.Source -B $vault shred
    }
    exit $LASTEXITCODE
} catch {
    Write-Host "Removal invocation failed; do not assume files were removed."
    exit 1
}
