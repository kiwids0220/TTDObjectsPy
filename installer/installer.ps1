[CmdletBinding()]
param(
    [string]$InstallPath,
    [string]$TracePath,
    [string]$InstallerPath,
    [string]$CMakePath,
    [string]$PythonPath,
    [string]$VenvPath,
    [string]$PythonPackageId = "Python.Python.3.13",
    [switch]$SkipBuild,
    [switch]$SkipVerify,
    [switch]$SkipCodexSetup,
    [switch]$ForceInstall,
    [switch]$ForceCodexSetup,
    [switch]$FullVerify
)

$ErrorActionPreference = "Stop"
$script:InstallerStopwatch = [System.Diagnostics.Stopwatch]::StartNew()

function Write-Step {
    param([string]$Message)
    Write-Host ("[{0:HH:mm:ss.fff}] [STEP] {1}" -f (Get-Date), $Message)
}

function Write-Detail {
    param([string]$Message)
    Write-Host ("[{0:HH:mm:ss.fff}] [INFO] {1}" -f (Get-Date), $Message)
}

function Write-WarningMessage {
    param([string]$Message)
    Write-Warning ("[{0:HH:mm:ss.fff}] [WARN] {1}" -f (Get-Date), $Message)
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=" * 78)
    Write-Host $Title
    Write-Host ("=" * 78)
}

function Write-CommandLine {
    param(
        [string]$Command,
        [object[]]$Arguments = @()
    )

    $formattedArguments = foreach ($argument in $Arguments) {
        $text = [string]$argument
        if ($text -match '[\s"]') {
            '"{0}"' -f ($text -replace '"', '\"')
        } else {
            $text
        }
    }

    Write-Detail ("Command: {0} {1}" -f $Command, ($formattedArguments -join " "))
}

function Write-FileDetails {
    param(
        [string]$Label,
        [string]$Path,
        [switch]$IncludeHash
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Write-WarningMessage "${Label} does not exist: $Path"
        return
    }

    $file = Get-Item -LiteralPath $Path
    Write-Detail ("{0}: {1}" -f $Label, $file.FullName)
    Write-Detail ("{0} size: {1:N0} bytes; modified: {2:O}" -f $Label, $file.Length, $file.LastWriteTimeUtc)
    if ($IncludeHash) {
        $hash = Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256
        Write-Detail ("{0} SHA256: {1}" -f $Label, $hash.Hash)
    }
}

function Assert-NativeSuccess {
    param(
        [string]$Description,
        [int[]]$AllowedExitCodes = @(0)
    )

    Write-Detail ("{0} exit code: {1}; allowed: {2}" -f $Description, $LASTEXITCODE, ($AllowedExitCodes -join ", "))
    if ($LASTEXITCODE -notin $AllowedExitCodes) {
        throw "$Description failed with exit code $LASTEXITCODE."
    }
}

function Get-NativeExitDescription {
    param([int]$ExitCode)

    $unsignedExitCode = [uint32]([int64]$ExitCode -band 0xffffffffL)
    $hexExitCode = "0x{0:X8}" -f $unsignedExitCode

    switch ($unsignedExitCode) {
        0xC0000135 {
            return "$hexExitCode (STATUS_DLL_NOT_FOUND: the executable could not start because a required DLL is missing)"
        }
        0xC000007B {
            return "$hexExitCode (STATUS_INVALID_IMAGE_FORMAT: executable or dependency architecture mismatch)"
        }
        default {
            return "$ExitCode ($hexExitCode)"
        }
    }
}

function Find-CMake {
    param([string]$RequestedPath)

    Write-Step "Locating CMake"
    if ($RequestedPath) {
        Write-Detail "Explicit CMake path requested: $RequestedPath"
        if (-not (Test-Path -LiteralPath $RequestedPath -PathType Leaf)) {
            Write-WarningMessage "The requested CMake executable does not exist: $RequestedPath"
            throw "CMake executable not found: $RequestedPath"
        }
        $resolved = (Resolve-Path -LiteralPath $RequestedPath).Path
        Write-Detail "Using explicit CMake executable: $resolved"
        return $resolved
    }

    Write-Detail "Checking PATH for cmake.exe"
    $command = Get-Command cmake.exe -ErrorAction SilentlyContinue
    if ($command) {
        Write-Detail "Found CMake on PATH: $($command.Source)"
        return $command.Source
    }

    $candidates = @(
        "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe",
        "C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe",
        "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe",
        "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
    )

    foreach ($candidate in $candidates) {
        Write-Detail "Checking CMake candidate: $candidate"
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            Write-Detail "Found Visual Studio CMake: $candidate"
            return $candidate
        }
        Write-WarningMessage "CMake candidate does not exist: $candidate"
    }

    Write-WarningMessage "No usable CMake executable was found on PATH or in Visual Studio 2022 locations"
    throw "CMake was not found. Install Visual Studio 2022 C++ build tools or pass -CMakePath."
}

function Find-BasePython {
    param(
        [string]$RequestedPath
    )

    Write-Step "Locating compatible Python interpreter"
    if ($RequestedPath) {
        Write-Detail "Explicit Python path requested: $RequestedPath"
        if (-not (Test-Path -LiteralPath $RequestedPath -PathType Leaf)) {
            Write-WarningMessage "The requested Python executable does not exist: $RequestedPath"
            throw "Python executable not found: $RequestedPath"
        }
        $resolved = (Resolve-Path -LiteralPath $RequestedPath).Path
        & $resolved -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)"
        if ($LASTEXITCODE -ne 0) {
            throw "Python 3.10 or newer is required: $resolved"
        }
        Write-Detail "Using explicit Python executable: $resolved"
        return @{
            Command = $resolved
            Arguments = @()
        }
    }

    Write-Detail "Checking PATH for py.exe"
    $launcher = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($launcher) {
        & $launcher.Source -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Detail "Using Python launcher: $($launcher.Source) -3"
            return @{ Command = $launcher.Source; Arguments = @("-3") }
        }
        Write-WarningMessage "py.exe exists but did not resolve Python 3.10 or newer"
    }
    else {
        Write-WarningMessage "Python launcher py.exe was not found on PATH"
    }

    Write-Detail "Checking PATH for python.exe"
    $python = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($python) {
        if ($python.Source -match '\\WindowsApps\\') {
            Write-WarningMessage "Ignoring Microsoft Store python.exe app-execution alias: $($python.Source)"
        } else {
            & $python.Source -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-Detail "Using Python executable from PATH: $($python.Source)"
                return @{ Command = $python.Source; Arguments = @() }
            }
            Write-WarningMessage "python.exe exists on PATH but is older than Python 3.10 or unusable"
        }
    }
    else {
        Write-WarningMessage "Python executable python.exe was not found on PATH"
    }

    $candidatePatterns = @(
        (Join-Path $env:LOCALAPPDATA "Programs\Python\Python*\python.exe"),
        (Join-Path $env:ProgramFiles "Python*\python.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "Python*\python.exe"),
        "C:\Python*\python.exe"
    ) | Where-Object { $_ }

    $candidates = foreach ($pattern in $candidatePatterns) {
        Write-Detail "Checking installed Python pattern: $pattern"
        Get-Item -Path $pattern -ErrorAction SilentlyContinue
    }

    foreach ($candidate in $candidates | Sort-Object FullName -Descending -Unique) {
        & $candidate.FullName -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Detail "Using installed Python executable: $($candidate.FullName)"
            return @{ Command = $candidate.FullName; Arguments = @() }
        }
    }

    return $null
}

function Install-Python {
    param([string]$PackageId)

    Write-WarningMessage "Python 3.10 or newer was not found; automatic installation is required"
    $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
    if (-not $winget) {
        throw "Python is missing and winget.exe is unavailable. Install Python 3.10+ or pass -PythonPath."
    }

    Write-Step "Installing Python with Windows Package Manager"
    $arguments = @(
        "install",
        "--id", $PackageId,
        "--exact",
        "--source", "winget",
        "--scope", "user",
        "--silent",
        "--disable-interactivity",
        "--accept-package-agreements",
        "--accept-source-agreements"
    )
    Write-CommandLine -Command $winget.Source -Arguments $arguments

    $previousConsoleEncoding = [Console]::OutputEncoding
    try {
        # winget emits UTF-8 progress glyphs. A PowerShell 5.1 pipeline decodes them
        # using the legacy console code page, so let winget write directly to a
        # UTF-8 console instead of piping its output through Out-Host.
        Write-Detail ("Temporarily changing console output encoding from {0} to UTF-8 for winget" -f $previousConsoleEncoding.WebName)
        [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
        & $winget.Source @arguments
    }
    finally {
        [Console]::OutputEncoding = $previousConsoleEncoding
    }
    Assert-NativeSuccess "Python installation"

    Write-Detail "Refreshing process PATH from machine and user environment"
    $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $env:Path = @($machinePath, $userPath) -join ";"

    $python = Find-BasePython
    if (-not $python) {
        throw "Python installation completed but no compatible interpreter could be located."
    }
    return $python
}

function Get-OrInstallBasePython {
    param(
        [string]$RequestedPath,
        [string]$PackageId
    )

    $python = Find-BasePython -RequestedPath $RequestedPath
    if ($python) {
        return $python
    }

    if ($RequestedPath) {
        throw "The requested Python interpreter is unavailable."
    }
    return Install-Python -PackageId $PackageId
}

function Get-VerificationPython {
    param(
        [string]$RequestedPath,
        [string]$VirtualEnvironmentPath,
        [string]$PackageId
    )

    if ($RequestedPath) {
        Write-Detail "Bypassing managed virtual environment because -PythonPath was supplied"
        return Get-OrInstallBasePython -RequestedPath $RequestedPath -PackageId $PackageId
    }

    $venvPython = Join-Path $VirtualEnvironmentPath "Scripts\python.exe"
    Write-Detail "Expected virtual environment interpreter: $venvPython"
    if (-not (Test-Path -LiteralPath $venvPython -PathType Leaf)) {
        Write-WarningMessage "Virtual environment interpreter does not exist and will be created: $venvPython"
        $basePython = Get-OrInstallBasePython -PackageId $PackageId
        Write-Step "Creating Python virtual environment at $VirtualEnvironmentPath"
        Write-CommandLine -Command $basePython.Command -Arguments (@($basePython.Arguments) + @("-m", "venv", $VirtualEnvironmentPath))
        & $basePython.Command @($basePython.Arguments) -m venv $VirtualEnvironmentPath
        Assert-NativeSuccess "Python virtual environment creation"
    } else {
        Write-Detail "Reusing existing virtual environment"
    }

    Write-FileDetails -Label "Verification Python" -Path $venvPython
    return @{ Command = $venvPython; Arguments = @() }
}

function Get-CodexCommand {
    $codex = Get-Command codex -ErrorAction SilentlyContinue
    if (-not $codex) {
        Write-WarningMessage "Codex is not installed or is not available on PATH"
        throw "Codex must be installed before running this installer, or use -SkipCodexSetup."
    }

    Write-Detail "Codex executable: $($codex.Source)"
    Write-CommandLine -Command $codex.Source -Arguments @("--version")
    & $codex.Source --version | Out-Host
    Assert-NativeSuccess "Codex version check"
    return $codex.Source
}

function Install-CodexIntegration {
    param(
        [string]$CodexPath,
        [string]$RepoRoot,
        [hashtable]$Python,
        [switch]$Force
    )

    Write-Section "Codex Integration"
    $marketplaceName = "ttdobjectspy-local"
    $pluginId = "ttdobjectspy@$marketplaceName"
    $launcherPath = Join-Path $RepoRoot "scripts\run_codex_mcp.py"
    $skillSource = Join-Path $RepoRoot "skills\ttd-analysis"
    $codexHome = if ($env:CODEX_HOME) {
        [System.IO.Path]::GetFullPath($env:CODEX_HOME)
    } else {
        Join-Path $HOME ".codex"
    }
    $skillRoot = Join-Path $codexHome "skills"
    $skillTarget = Join-Path $skillRoot "ttd-analysis"
    Write-Detail "Codex home: $codexHome"

    Write-FileDetails -Label "Codex MCP launcher" -Path $launcherPath
    if (-not (Test-Path -LiteralPath $skillSource -PathType Container)) {
        Write-WarningMessage "Bundled TTD skill directory does not exist: $skillSource"
        throw "Bundled Codex skill is missing."
    }

    Write-Step "Checking Codex marketplace registration"
    Write-CommandLine -Command $CodexPath -Arguments @("plugin", "marketplace", "list", "--json")
    $marketplaceJson = (& $CodexPath plugin marketplace list --json 2>&1 | Out-String)
    Assert-NativeSuccess "Codex marketplace listing"
    $marketplaceJson.TrimEnd() | Out-Host
    $marketplaceState = $marketplaceJson | ConvertFrom-Json
    $marketplaceEntry = @($marketplaceState.marketplaces) |
        Where-Object { $_.name -eq $marketplaceName } |
        Select-Object -First 1

    $normalizedRepoRoot = [System.IO.Path]::GetFullPath($RepoRoot).TrimEnd([char[]]@("\", "/"))
    $marketplaceRegistered = $false
    if ($marketplaceEntry) {
        $registeredRoot = [System.IO.Path]::GetFullPath([string]$marketplaceEntry.root).TrimEnd([char[]]@("\", "/"))
        $marketplaceRegistered = $registeredRoot -ieq $normalizedRepoRoot

        if ($marketplaceRegistered) {
            Write-Detail "Marketplace is already registered at the active repository path: $registeredRoot"
        } else {
            Write-WarningMessage "Marketplace '$marketplaceName' is registered at a different path: $registeredRoot"
            Write-Step "Removing stale TTDObjectsPy marketplace registration"
            Write-CommandLine -Command $CodexPath -Arguments @("plugin", "marketplace", "remove", $marketplaceName, "--json")
            & $CodexPath plugin marketplace remove $marketplaceName --json
            Assert-NativeSuccess "Stale Codex marketplace removal"
        }
    }

    if (-not $marketplaceRegistered) {
        Write-Step "Registering local TTDObjectsPy marketplace"
        Write-CommandLine -Command $CodexPath -Arguments @("plugin", "marketplace", "add", $RepoRoot, "--json")
        & $CodexPath plugin marketplace add $RepoRoot --json
        Assert-NativeSuccess "Codex marketplace registration"
    }

    Write-Step "Checking Codex plugin availability"
    Write-CommandLine -Command $CodexPath -Arguments @("plugin", "list", "--available", "--json")
    $pluginStateJson = (& $CodexPath plugin list --available --json | Out-String)
    Assert-NativeSuccess "Codex plugin listing"
    $pluginState = $pluginStateJson | ConvertFrom-Json
    $pluginEntry = @($pluginState.installed) + @($pluginState.available) |
        Where-Object { $_.pluginId -eq $pluginId } |
        Select-Object -First 1
    if (-not $pluginEntry) {
        throw "Codex marketplace registration succeeded but plugin '$pluginId' is unavailable."
    }
    Write-Detail "Plugin available: $($pluginEntry.pluginId); installed=$($pluginEntry.installed); enabled=$($pluginEntry.enabled)"

    Write-Step "Configuring global Codex MCP server"
    $savedErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        & $CodexPath mcp get ttdobjectspy 2>$null | Out-Null
        $mcpExists = $LASTEXITCODE -eq 0
    }
    finally {
        $ErrorActionPreference = $savedErrorActionPreference
    }
    if ($mcpExists) {
        Write-Detail "Existing MCP server 'ttdobjectspy' will be replaced with the managed venv configuration"
        Write-CommandLine -Command $CodexPath -Arguments @("mcp", "remove", "ttdobjectspy")
        & $CodexPath mcp remove ttdobjectspy
        Assert-NativeSuccess "Existing Codex MCP removal"
    }

    $mcpArguments = @("mcp", "add", "ttdobjectspy", "--", $Python.Command) + @($Python.Arguments) + @($launcherPath)
    Write-CommandLine -Command $CodexPath -Arguments $mcpArguments
    & $CodexPath @mcpArguments
    Assert-NativeSuccess "Codex MCP registration"

    Write-Step "Exposing the bundled TTD analysis skill globally"
    New-Item -ItemType Directory -Force -Path $skillRoot | Out-Null
    if (Test-Path -LiteralPath $skillTarget) {
        $existingSkill = Get-Item -LiteralPath $skillTarget -Force
        $isLink = [bool]($existingSkill.Attributes -band [IO.FileAttributes]::ReparsePoint)
        $sameTarget = $isLink -and $existingSkill.Target -and
            ([System.IO.Path]::GetFullPath([string]$existingSkill.Target) -eq [System.IO.Path]::GetFullPath($skillSource))

        if ($sameTarget) {
            Write-Detail "Skill junction already points to the bundled skill: $skillTarget"
        } elseif ($isLink) {
            Write-WarningMessage "Skill junction points to a different repository path: $($existingSkill.Target)"
            Write-Step "Removing stale TTD analysis skill junction"
            Remove-Item -LiteralPath $skillTarget -Recurse -Force
        } elseif ($Force) {
            Write-WarningMessage "Replacing existing skill path because -ForceCodexSetup was specified: $skillTarget"
            Remove-Item -LiteralPath $skillTarget -Recurse -Force
        } else {
            throw "A different path already exists at $skillTarget. Use -ForceCodexSetup to replace it."
        }
    }

    if (-not (Test-Path -LiteralPath $skillTarget)) {
        New-Item -ItemType Junction -Path $skillTarget -Target $skillSource | Out-Null
        Write-Detail "Created skill junction: $skillTarget -> $skillSource"
    }

    Write-Step "Verifying Codex MCP registration"
    Write-CommandLine -Command $CodexPath -Arguments @("mcp", "get", "ttdobjectspy")
    & $CodexPath mcp get ttdobjectspy
    Assert-NativeSuccess "Codex MCP verification"
    Write-Detail "Codex integration is installed. Restart Codex or start a new Codex process before using the plugin."
}

function Install-VerificationDependencies {
    param(
        [hashtable]$Python,
        [string]$RepoRoot
    )

    $dependencyProbe = @'
import importlib.metadata
import importlib.util
import sys

packages = ("mcp", "capstone")
missing = [name for name in packages if importlib.util.find_spec(name) is None]
print("Dependency probe:")
for name in packages:
    if name in missing:
        print(f"  {name}: MISSING")
    else:
        try:
            print(f"  {name}: {importlib.metadata.version(name)}")
        except importlib.metadata.PackageNotFoundError:
            print(f"  {name}: importable, distribution version unavailable")
sys.exit(1 if missing else 0)
'@
    $dependencyProbeBytes = [System.Text.Encoding]::UTF8.GetBytes($dependencyProbe)
    $dependencyProbeBase64 = [Convert]::ToBase64String($dependencyProbeBytes)
    $dependencyProbeCommand = "import base64; exec(base64.b64decode('$dependencyProbeBase64'))"

    Write-Step "Checking Python verification dependencies"
    Write-CommandLine -Command $Python.Command -Arguments (@($Python.Arguments) + @("-c", "<dependency probe>"))
    & $Python.Command @($Python.Arguments) -c $dependencyProbeCommand
    Write-Detail "Dependency probe exit code: $LASTEXITCODE"
    if ($LASTEXITCODE -eq 0) {
        Write-Detail "All required verification dependencies are already installed"
        return
    }

    Write-Step "Installing Python verification dependencies"
    Write-CommandLine -Command $Python.Command -Arguments (@($Python.Arguments) + @("-m", "pip", "install", "-e", "${RepoRoot}[dataflow]"))
    & $Python.Command @($Python.Arguments) -m pip install -e "${RepoRoot}[dataflow]"
    Assert-NativeSuccess "Python dependency installation"

    Write-Step "Rechecking Python verification dependencies after installation"
    & $Python.Command @($Python.Arguments) -c $dependencyProbeCommand
    Assert-NativeSuccess "Python dependency verification"
}

$installerDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $installerDir

Write-Section "TTDObjectsPy Runtime Installer"
Write-Detail "Start time: $((Get-Date).ToString('O'))"
Write-Detail "PowerShell version: $($PSVersionTable.PSVersion)"
Write-Detail "PowerShell edition: $($PSVersionTable.PSEdition)"
Write-Detail "Operating system: $([System.Environment]::OSVersion.VersionString)"
Write-Detail "Process architecture: $([System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture)"
Write-Detail "OS architecture: $([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture)"
Write-Detail "Current user: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
Write-Detail "Elevated: $(([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))"
Write-Detail "Current directory: $(Get-Location)"
Write-Detail "Script path: $($MyInvocation.MyCommand.Path)"
Write-Detail "Installer directory: $installerDir"
Write-Detail "Repository root: $repoRoot"
Write-Detail "Parameters:"
Write-Detail "  InstallPath = $(if ($InstallPath) { $InstallPath } else { '<default>' })"
Write-Detail "  TracePath = $(if ($TracePath) { $TracePath } else { '<auto-detect>' })"
Write-Detail "  InstallerPath = $(if ($InstallerPath) { $InstallerPath } else { '<auto-detect>' })"
Write-Detail "  CMakePath = $(if ($CMakePath) { $CMakePath } else { '<auto-detect>' })"
Write-Detail "  PythonPath = $(if ($PythonPath) { $PythonPath } else { '<managed venv>' })"
Write-Detail "  VenvPath = $(if ($VenvPath) { $VenvPath } else { '<default>' })"
Write-Detail "  PythonPackageId = $PythonPackageId"
Write-Detail "  SkipBuild = $SkipBuild"
Write-Detail "  SkipVerify = $SkipVerify"
Write-Detail "  SkipCodexSetup = $SkipCodexSetup"
Write-Detail "  ForceInstall = $ForceInstall"
Write-Detail "  ForceCodexSetup = $ForceCodexSetup"
Write-Detail "  FullVerify = $FullVerify"

if (-not $InstallPath) {
    $InstallPath = Join-Path $repoRoot "asset"
}
$InstallPath = [System.IO.Path]::GetFullPath($InstallPath)
if (-not $VenvPath) {
    $VenvPath = Join-Path $repoRoot ".venv"
}
$VenvPath = [System.IO.Path]::GetFullPath($VenvPath)
Write-Detail "Resolved installation path: $InstallPath"
Write-Detail "Resolved virtual environment path: $VenvPath"

$buildDir = Join-Path $installerDir "build-vs2022"
$bundledInstallerExe = Join-Path $installerDir "ttd-installer.exe"
$builtInstallerExe = Join-Path $buildDir "out\Release\ttd-installer.exe"
Write-Detail "Build directory: $buildDir"
Write-Detail "Bundled installer candidate: $bundledInstallerExe"
Write-Detail "Built installer candidate: $builtInstallerExe"

Write-Section "Installer Executable Selection"
if ($InstallerPath) {
    Write-Detail "An explicit installer path was supplied"
    if (-not (Test-Path -LiteralPath $InstallerPath -PathType Leaf)) {
        Write-WarningMessage "The requested installer executable does not exist: $InstallerPath"
        throw "Installer executable not found: $InstallerPath"
    }
    $installerExe = (Resolve-Path -LiteralPath $InstallerPath).Path
} elseif (Test-Path -LiteralPath $bundledInstallerExe -PathType Leaf) {
    $installerExe = $bundledInstallerExe
    Write-Step "Using bundled installer executable $installerExe"
} elseif ($SkipBuild) {
    Write-Detail "Bundled installer is absent and building is disabled"
    Write-WarningMessage "Bundled installer does not exist: $bundledInstallerExe"
    Write-WarningMessage "Built installer was not considered because -SkipBuild was specified: $builtInstallerExe"
    throw "Installer executable is missing and -SkipBuild was specified."
} else {
    Write-WarningMessage "Bundled installer does not exist; attempting a source build: $bundledInstallerExe"
    Write-Detail "Bundled installer is absent; a local build is required"
    $cmake = Find-CMake -RequestedPath $CMakePath
    Write-Step "Configuring installer build"
    Write-CommandLine -Command $cmake -Arguments @("-S", $installerDir, "-B", $buildDir, "-G", "Visual Studio 17 2022", "-A", "x64")
    & $cmake -S $installerDir -B $buildDir -G "Visual Studio 17 2022" -A x64
    Assert-NativeSuccess "CMake configure"

    Write-Step "Building installer"
    Write-CommandLine -Command $cmake -Arguments @("--build", $buildDir, "--config", "Release")
    & $cmake --build $buildDir --config Release
    Assert-NativeSuccess "CMake build"
    $installerExe = $builtInstallerExe
}

if (-not (Test-Path -LiteralPath $installerExe -PathType Leaf)) {
    Write-WarningMessage "Selected installer executable does not exist after discovery/build: $installerExe"
    throw "Installer executable not found: $installerExe"
}
Write-FileDetails -Label "Selected installer" -Path $installerExe -IncludeHash

Write-Section "Runtime Installation State"
Write-Step "Checking local runtime installation state"
Write-CommandLine -Command $installerExe -Arguments @("version", "--path", $InstallPath, "--json")
& $installerExe version --path $InstallPath --json
$versionExitCode = $LASTEXITCODE
Write-Detail "Local runtime status exit code: $versionExitCode (0=installed, 1=not installed)"

if ($versionExitCode -eq 0 -and -not $ForceInstall) {
    Write-Detail "Runtime exists and ForceInstall is false; checking the online version"
    Write-Step "Checking for runtime updates"
    Write-CommandLine -Command $installerExe -Arguments @("check-update", "--path", $InstallPath, "--json")
    & $installerExe check-update --path $InstallPath --json
    $updateExitCode = $LASTEXITCODE
    Write-Detail "Update check exit code: $updateExitCode (0=current, 2=update available)"

    if ($updateExitCode -eq 0) {
        Write-Step "Runtime is already installed and current"
    } elseif ($updateExitCode -eq 2) {
        Write-Step "Updating runtime in $InstallPath"
        Write-CommandLine -Command $installerExe -Arguments @("install", "--path", $InstallPath, "--update")
        & $installerExe install --path $InstallPath --update
        Assert-NativeSuccess "Runtime update"
    } else {
        throw "Runtime update check failed with exit code $updateExitCode."
    }
} elseif ($versionExitCode -eq 0) {
    Write-Detail "Runtime exists and ForceInstall is true"
    Write-Step "Reinstalling runtime in $InstallPath"
    Write-CommandLine -Command $installerExe -Arguments @("install", "--path", $InstallPath, "--update")
    & $installerExe install --path $InstallPath --update
    Assert-NativeSuccess "Runtime reinstall"
} elseif ($versionExitCode -eq 1) {
    Write-Detail "No existing runtime was detected"
    Write-Step "Installing runtime into $InstallPath"
    Write-CommandLine -Command $installerExe -Arguments @("install", "--path", $InstallPath)
    & $installerExe install --path $InstallPath
    Assert-NativeSuccess "Runtime installation"
} else {
    $exitDescription = Get-NativeExitDescription -ExitCode $versionExitCode
    Write-WarningMessage "The installer executable failed to start or query the runtime: $exitDescription"
    throw "Runtime status check failed with exit code $exitDescription."
}

if ($SkipVerify -and $SkipCodexSetup) {
    Write-Section "Installation Complete"
    Write-Detail "Verification and Codex setup were skipped"
    Write-Detail ("Total elapsed time: {0}" -f $script:InstallerStopwatch.Elapsed)
    return
}

Write-Section "Python Verification Environment"
$python = Get-VerificationPython -RequestedPath $PythonPath -VirtualEnvironmentPath $VenvPath -PackageId $PythonPackageId
Write-Detail "Verification interpreter command: $($python.Command)"
Write-Detail "Verification interpreter prefix arguments: $($python.Arguments -join ' ')"
Write-CommandLine -Command $python.Command -Arguments (@($python.Arguments) + @("-c", "import platform, sys; print(...)"))
& $python.Command @($python.Arguments) -c "import platform, sys; print(f'Python executable: {sys.executable}'); print(f'Python version: {sys.version}'); print(f'Python architecture: {platform.architecture()[0]}'); print(f'Python prefix: {sys.prefix}'); print(f'Base prefix: {sys.base_prefix}'); print(f'Virtual environment active: {sys.prefix != sys.base_prefix}')"
Assert-NativeSuccess "Python interpreter inspection"
Install-VerificationDependencies -Python $python -RepoRoot $repoRoot

if (-not $SkipCodexSetup) {
    $codex = Get-CodexCommand
    Install-CodexIntegration -CodexPath $codex -RepoRoot $repoRoot -Python $python -Force:$ForceCodexSetup
} else {
    Write-WarningMessage "Codex integration setup was skipped because -SkipCodexSetup was specified"
}

if ($SkipVerify) {
    Write-Section "Installation Complete"
    Write-Detail "Runtime installation and Codex setup completed"
    Write-Detail "Verification was skipped because -SkipVerify was specified"
    Write-Detail ("Total elapsed time: {0}" -f $script:InstallerStopwatch.Elapsed)
    return
}

Write-Section "Installed Runtime Inspection"
$ttdDllPath = Join-Path $InstallPath "amd64\ttd\TTDReplay.dll"
if (-not (Test-Path -LiteralPath $ttdDllPath -PathType Leaf)) {
    Write-WarningMessage "Required installed runtime file does not exist: $ttdDllPath"
    throw "Installed TTDReplay.dll was not found: $ttdDllPath"
}
Write-FileDetails -Label "TTDReplay.dll" -Path $ttdDllPath -IncludeHash
$runtimeFiles = Get-ChildItem -LiteralPath $InstallPath -Recurse -File -ErrorAction SilentlyContinue
Write-Detail "Installed runtime file count: $($runtimeFiles.Count)"
Write-Detail ("Installed runtime total size: {0:N0} bytes" -f (($runtimeFiles | Measure-Object Length -Sum).Sum))
foreach ($runtimeFile in $runtimeFiles | Sort-Object FullName) {
    Write-Detail ("Runtime file: {0} ({1:N0} bytes)" -f $runtimeFile.FullName, $runtimeFile.Length)
}

Write-Section "Trace Selection"
if (-not $TracePath) {
    Write-Detail "No trace path was supplied; searching C:\traces recursively"
    if (-not (Test-Path -LiteralPath "C:\traces" -PathType Container)) {
        Write-WarningMessage "Default trace search directory does not exist: C:\traces"
    }
    $latestTrace = Get-ChildItem -Path "C:\traces" -Recurse -Filter *.run -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    if ($latestTrace) {
        $TracePath = $latestTrace.FullName
        Write-Detail "Selected most recently modified trace: $TracePath"
    } else {
        Write-WarningMessage "No .run trace files were found under C:\traces; smoke verification will only load the DLL"
    }
} elseif (-not (Test-Path -LiteralPath $TracePath -PathType Leaf)) {
    Write-WarningMessage "The requested trace file does not exist: $TracePath"
    throw "Trace file not found: $TracePath"
} else {
    Write-Detail "Using explicitly supplied trace: $TracePath"
}
if ($TracePath) {
    Write-FileDetails -Label "Verification trace" -Path $TracePath
}

$previousDllPath = $env:TTD_DLL_PATH
$previousTrace = $env:TTD_TEST_TRACE
Write-Section "Verification Environment Overrides"
Write-Detail "Previous TTD_DLL_PATH: $(if ($previousDllPath) { $previousDllPath } else { '<unset>' })"
Write-Detail "Previous TTD_TEST_TRACE: $(if ($previousTrace) { $previousTrace } else { '<unset>' })"
$env:TTD_DLL_PATH = $ttdDllPath
if ($TracePath) {
    $env:TTD_TEST_TRACE = $TracePath
} else {
    Remove-Item Env:TTD_TEST_TRACE -ErrorAction SilentlyContinue
}
Write-Detail "Verification TTD_DLL_PATH: $env:TTD_DLL_PATH"
Write-Detail "Verification TTD_TEST_TRACE: $(if ($env:TTD_TEST_TRACE) { $env:TTD_TEST_TRACE } else { '<unset>' })"

Write-Section "Runtime Verification"
Push-Location $repoRoot
try {
    Write-Detail "Verification working directory: $(Get-Location)"
    if ($FullVerify) {
        if (-not $TracePath) {
            Write-WarningMessage "Full verification cannot run because no trace file was supplied or discovered"
            throw "-FullVerify requires -TracePath or a .run file under C:\traces."
        }

        Write-Step "Running full runtime verification with $TracePath"
        Write-CommandLine -Command $python.Command -Arguments (@($python.Arguments) + @("-m", "unittest", "tests.test_installer_runtime", "-v"))
        & $python.Command @($python.Arguments) -m unittest tests.test_installer_runtime -v
        Assert-NativeSuccess "Full runtime verification"
    } else {
        $traceDescription = if ($TracePath) { " and opening $TracePath" } else { "" }
        Write-Step "Loading installed runtime$traceDescription"
        Write-CommandLine -Command $python.Command -Arguments (@($python.Arguments) + @("-c", "<runtime smoke verification>"))
        & $python.Command @($python.Arguments) -c "import os; from test_all_functions import verify_installed_runtime; print(verify_installed_runtime(os.environ.get('TTD_TEST_TRACE')))"
        Assert-NativeSuccess "Runtime verification"
    }
}
finally {
    Pop-Location
    Write-Detail "Restoring previous verification environment variables"
    $env:TTD_DLL_PATH = $previousDllPath
    if ($null -eq $previousTrace) {
        Remove-Item Env:TTD_TEST_TRACE -ErrorAction SilentlyContinue
    } else {
        $env:TTD_TEST_TRACE = $previousTrace
    }
    Write-Detail "Environment restoration complete"
}

Write-Section "Installation And Verification Complete"
Write-Detail "Runtime path: $InstallPath"
Write-Detail "Installer executable: $installerExe"
Write-Detail "Python executable: $($python.Command)"
Write-Detail "Trace verified: $(if ($TracePath) { $TracePath } else { '<DLL load only>' })"
Write-Detail "Verification mode: $(if ($FullVerify) { 'full test suite' } else { 'smoke test' })"
Write-Detail "End time: $((Get-Date).ToString('O'))"
Write-Detail ("Total elapsed time: {0}" -f $script:InstallerStopwatch.Elapsed)
