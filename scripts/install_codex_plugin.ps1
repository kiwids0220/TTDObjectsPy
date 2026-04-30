[CmdletBinding()]
param(
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$installer = Join-Path $repoRoot "installer\installer.ps1"
& $installer -SkipBuild -SkipVerify -ForceCodexSetup:$Force
exit $LASTEXITCODE
