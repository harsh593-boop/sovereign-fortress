# Compatibility wrapper for the single checked native DPAPI implementation.
param (
    [Parameter(Mandatory=$true)]
    [ValidateSet("Lock", "Unlock")]
    [string]$Action,
    [string[]]$AdditionalFiles = @()
)
$ErrorActionPreference = "Stop"
if ($AdditionalFiles.Count -gt 0) {
    Write-Error "Arbitrary AdditionalFiles are no longer processed. Use the private client directory or explicitly set FORTRESS_VAULT_SSH_KEY for one intended key."
    exit 1
}
try {
    $python = Get-Command python.exe -ErrorAction Stop
    & $python.Source -B (Join-Path $PSScriptRoot "fortress_vault.py") $Action.ToLowerInvariant()
    exit $LASTEXITCODE
} catch {
    Write-Host "Vault invocation failed. No success or erasure claim is made."
    exit 1
}
