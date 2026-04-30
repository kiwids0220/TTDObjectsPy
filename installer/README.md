# TTD Installer

This folder contains the standalone Windows installer sources for the TTD runtime payload extracted from the WinDbg package.

Current release tag: `installer-v1.2603.20001.0` (also recorded in `RELEASE.txt`).

Layout:
- `ttd-installer.exe` and `installer.ps1` are the release entry points.
- `src/` contains the installer implementation.
- `include/` contains public headers.
- `vendor/` contains third-party dependencies.

## Prerequisites

- **Windows 10/11** (x64)
- **Codex CLI** installed and available on `PATH`
- **Windows Package Manager (`winget`)** only when Python is not already installed
- **A `.run` trace file** if you want post-install verification to open a trace
- **Network access** to download the WinDbg package during installation

The normal bundled-installer path does not require Git, Visual Studio, CMake, or a
pre-existing Python installation. Visual Studio Build Tools are only required when
`installer\ttd-installer.exe` is missing and must be rebuilt.

## Build

```powershell
$cmake = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
& $cmake -S . -B build-vs2022 -G 'Visual Studio 17 2022' -A x64
& $cmake --build build-vs2022 --config Release
```

The compiled binary is written to:

```text
build-vs2022\out\Release\ttd-installer.exe
```

For release use, keep a copy next to the script as `installer\ttd-installer.exe`. `installer.ps1` will use that bundled executable first and only build if it is missing.
The release executable links the MSVC runtime statically so it runs on clean Windows
installations without the Visual C++ Redistributable.

## Run

```powershell
.\ttd-installer.exe install --path ..\asset
```

The extracted binaries are written under the repo root `asset\amd64` folder, including `..\asset\amd64\ttd\TTD.exe` and the required debugger runtime DLLs.

## Install And Verify

```powershell
.\installer.ps1
```

The script uses the bundled installer when present, skips the large package download when
the installed runtime is current, and performs a DLL load smoke test. If a trace is supplied
with `-TracePath` (or found under `C:\traces`), the smoke test also opens it.

Use `-ForceInstall` to reinstall, `-FullVerify` to run the comprehensive trace suite, and
`-SkipVerify` for installation only. Tool locations can be overridden with `-InstallerPath`,
`-CMakePath`, and `-PythonPath`.

If Python 3.10+ is missing, the script installs Python 3.13 for the current user with
`winget`, creates the repo's `.venv`, and installs the core plus data-flow dependencies.
Use `-VenvPath` to place that environment elsewhere.

Codex setup is performed by default: the local marketplace is registered, the MCP server is
configured to use the managed venv, and the bundled skill is linked into `~/.codex/skills`.
Use `-SkipCodexSetup` for runtime-only installation or `-ForceCodexSetup` to replace an
existing conflicting skill path.

The script emits detailed diagnostics by default, including tool discovery, exact commands,
exit codes, file metadata and hashes, Python package versions, trace selection, and timing.
Missing installer, build-tool, Python, virtual-environment, runtime, and trace paths produce
explicit `[WARN]` messages before fallback behavior or a fatal error.

## Acknowledgments

This installer was inspired by the
[Binary Ninja debugger's WinDbg/TTD installer](https://github.com/Vector35/debugger/tree/dev/installer),
including its
[installer implementation](https://github.com/Vector35/debugger/blob/dev/installer/install_windbg.py)
and documented
[TTD installation workflow](https://docs.binary.ninja/guide/debugger/ttd.html).

Special thanks to **Xusheng Li (Xu Sheng) of Binary Ninja / Vector 35** for inspiration,
guidance, and mentorship.
