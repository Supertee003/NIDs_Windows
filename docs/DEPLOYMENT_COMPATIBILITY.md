# Windows deployment compatibility — declared vs tested

> Scope: build source `4dd3393` (HISTORICAL at current source `aa3b7b0`). AEGIS-PLAN-019.
> This page separates a declared target from a tested OS matrix. No OS version
> was tested while writing it.

## 1. Declared target

`docs/DEPLOYMENT.md` declares **Windows 10/11 x64**. The canonical runtime is:

| Build command | Artifact |
|---|---|
| `zig build` | `aegis_nids.exe` |
| `cargo build --release` | `aegis_pep.dll` |
| `cmake -B build && cmake --build build` | three native helper DLLs |
| `cd nose && go build -o aegis-nose.exe .` | `aegis-nose.exe` |
| `python brain/windows_brain.py` | interpreted analytics |
| TypeScript policy | advisory only, no production output |

Toolchain versions are pinned in `docs/runtime/TOOLCHAIN_INVENTORY.md` and
`build_truth.json`.

## 2. Tested OS matrix

| OS build | Architecture | Tested at current source | Evidence |
|---|---|---|---|
| Windows 10 x64 lab host | x64 | **NARROW E5/E6 PROOFS at `aa3b7b0`**; not an OS-compatibility matrix result | Loopback E6, S2/S3 E5 and 100/s load records in `analysis/current-head/raw-aa3b7b0-20261126/`; historical soak at `a53eda8` |
| Windows 11 x64 lab guest | x64 | **NOT_TESTED at `aa3b7b0`** | Historical isolated-lab records (`192.168.126.20`) at their own commits |
| Windows Server 2019 | x64 | **NOT_TESTED** | none |
| Windows Server 2022 | x64 | **NOT_TESTED** | none |
| Any WDK/minifilter-host combination | x64 | **NOT_PROVEN at `aa3b7b0`** | `docs/runtime/KERNEL_LIFECYCLE.md` |

A declare-only row is not a PASS row. Do not cite this page as compatibility
certification.

## 3. What a real matrix row needs

1. Exact OS build (for example `10.0.22631.x`), architecture, and host role.
2. Installed binary SHA-256 and build source commit.
3. Installer result and rollback path.
4. Driver/service/filter state before and after.
5. At least one positive and one negative control over the canonical pipe.
6. Raw transcript locator with SHA-256 and an evidence entry at that source.

## 4. Owner actions

Run the OS matrix rows that matter to the deployment target using
`analysis/current-head/OWNER-RUN-HOST-PROOF-RUNBOOK-20261126.md`, then replace
`NOT_TESTED` with the recorded result and evidence id. Until then the honest
status is "declared Windows 10/11 x64, tested matrix incomplete".

---

See also: [`DEPLOYMENT.md`](DEPLOYMENT.md),
[`runtime/KERNEL_LIFECYCLE.md`](runtime/KERNEL_LIFECYCLE.md),
[`runtime/TOOLCHAIN_INVENTORY.md`](runtime/TOOLCHAIN_INVENTORY.md).
