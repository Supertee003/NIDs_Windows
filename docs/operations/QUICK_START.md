# Local build and first start (detection-only)

> This page holds the detailed local build/verify commands moved out of `README.md`
> so the top-level document can stay an overview. It does not claim Windows E5,
> production qualification or a new release. Supported target: 64-bit Windows 10/11.
> Kernel-driver and WFP tests require an isolated test machine or disposable VM.  
> Product scope is fixed by [`docs/SCOPE.md`](../SCOPE.md) (detection-only / observe-only); current status comes from [`release/release-status.json`](../../release/release-status.json).

## Required build tools

| Component | Minimum | Purpose |
|---|---:|---|
| Zig | 0.13.0 | Core daemon and Zig tests |
| Rust | 1.75 or current stable MSVC toolchain | PEP, Shield, native dashboard |
| Go | 1.22+ | Go Nose acquisition |
| Python | 3.11+ | CLI, Brain, proof scripts, tests |
| CMake | 3.27+ | Native helper and bridge builds |
| Visual Studio 2022 | MSVC C++ workload | C/C++ compilation and Windows ABI |
| Windows SDK and WDK | Matching installed SDK | WFP kernel driver, headers and libraries |
| Git | Current | Source retrieval and provenance |
| PowerShell | Windows PowerShell 5.1 or PowerShell 7 | Build, service and proof scripts |

Install the **Desktop development with C++** workload. The WDK must provide kernel
headers, `ntoskrnl.lib` and WFP libraries. A driver that is only compiled but not
correctly signed is not a valid runtime artifact.

Optional lab tools: Npcap + Npcap SDK (live capture), Node.js 20+ (TypeScript policy
authoring), a hypervisor, and optionally a Kali VM as traffic generator. A typical
host-only lab is `Kali 192.168.126.10`, `Windows target 192.168.126.20`,
`development host 192.168.126.1`.

## Obtain the source

```powershell
git clone <repository-url> AEGIS-NIDS
Set-Location .\AEGIS-NIDS
```

If the repository arrives as an archive, verify its checksum and record the source
commit before building. Do not mix binaries from `Program Files`, an old release
bundle and the current checkout.

## First-time setup

Open an **elevated PowerShell** only when a step requires administrator access.

Check the toolchain:

```powershell
zig version
rustc --version
cargo --version
go version
python --version
cmake --version
```

Create runtime directories and a local deployment profile:

```powershell
New-Item -ItemType Directory -Force `
  logs\pids, logs\runtime, logs\health, logs\build, pid | Out-Null
Copy-Item config\deployment_profile.example.json config\deployment_profile.json
```

Do not place secrets, private policy signing keys or production credentials in the repository.

## Build from source

```powershell
.\scripts\build_all.bat
```

The build covers native helpers, Zig daemon, Rust components, Go ingress and
Python/Cython support. `SKIP` is not a successful production build: every required
component must report `OK`. Stop on `FAIL` or an unexpected `SKIP`.

Repository verification:

```powershell
python tools\release_engineering.py --manifest
python tools\release_engineering.py --verify
python tools\aegisctl.py rules validate
```

The authoritative artifact manifest and the current build output must agree. The
manifest owns the Go Nose filename; do not infer readiness from a stale `dist`,
`build` or `target` directory. Verify the current daemon path:

```powershell
Get-Item .\zig-out\bin\aegis_nids.exe
Get-FileHash .\zig-out\bin\aegis_nids.exe -Algorithm SHA256
```

The running process must later point to this build, not to an older executable.

## Start and verify detection-only mode

Start one daemon using the documented service or development procedure; the Zig
daemon must own the control pipe and worker lifecycle. Verify through the control plane:

```powershell
python tools\aegisctl.py status
python tools\aegisctl.py health
python tools\aegisctl.py diagnose
```

Expected safe posture:

```text
prevention_gate       = closed
tier3_enforcing       = false
host_effect_capable   = false
receipt_required      = true
```

`provider_ready=true` means a provider dependency is present or attested; it does
not mean traffic was blocked. Only a validated receipt can claim a confirmed host
effect.

## Where to go next

- Safe testing workflow and proof scripts: [`README.md` § Safe testing workflow](../../README.md#safe-testing-workflow)
- Operator runbook: [`docs/runtime/LOCAL_RUNBOOK.md`](../runtime/LOCAL_RUNBOOK.md)
- Build truth: [`docs/architecture/BUILD-TRUTH.md`](../architecture/BUILD-TRUTH.md)
- Release status (single source): [`release/release-status.json`](../../release/release-status.json)
