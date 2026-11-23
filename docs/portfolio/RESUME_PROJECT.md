# Resume project section — AEGIS NIDS Windows

> Copy the block below into a resume. Keep only the bullets that match your actual contribution.
> This is project evidence, not personal attribution — adjust verbs and scope to what you did.

---

## AEGIS NIDS Windows — Windows Kernel-Assisted Network Intrusion Detection System
**Detection-only NIDS | Zig · Go · Rust · C/C++ · Python · TypeScript | 2025–2026**

- Built a Windows-native, kernel-assisted **network intrusion detection system** spanning six languages: Zig runtime spine, Go Nose packet capture, C/C++ WFP/ETW/FIM/Registry adapters, Rust detection-only policy/crypto authority, Python analytics, and TypeScript policy authoring.
- Designed a **hub-and-spoke runtime** in which the Zig daemon is the single authority; every other language connects through C ABI/FFI, preventing language-to-language authority sprawl.
- Implemented a **canonical event pipeline** — one wire schema with byte-exact codecs in Zig, Go, C, and Python (Rust codec still TBD) — carrying Npcap packets over a length-prefixed named pipe into flow tracking, correlation, and a **23-rule** detection catalog (L4, L7, kernel file/process, and pipe layers).
- Enforced a **detection-only authority boundary**: `prevention_gate=closed`, `tier3_enforcing=false`, `host_effect_capable=false`; a `BLOCK` policy label is recorded as intent, never as a confirmed host effect.
- Added **hash-chained forensic records and IDS evidence receipts**, plus decision/audit traces, so every finding can be integrity-verified after the fact (replay is integrity-only; it does not re-execute detection).
- Proved the detection path on a real Windows host: bridged Kali → Windows attribution, R9006 SYN-burst detection with a **10-port negative control**, and a loopback full-path self-test with exact 5-tuple attribution and `host_effect_confirmed=false`.
- Shipped release `v1.1` as **SHIPPABLE (0/6 gates open)** with an Ed25519-signed manifest (`674/674` artifacts verified), an owner-run **36.52 h / 24 h soak PASS** with zero loss or shed counters in the recorded soak window, and a **1,471 passed / 0 skipped** Python result that is the sum of two phases at build source `a53eda8`, not a single `pytest` invocation.
- Produced operator tooling: CLI status/health/forensics, a read-only web dashboard, and machine-readable truth maps that are regenerated and verified against the build source commit after every change.

**Tech:** Zig, Go, Rust, C/C++, Python, TypeScript, Npcap, Windows WFP/ETW, named pipes, Ed25519, hash chains, SSE dashboard, pytest.

**Link:** github.com/Supertee003/NIDs_Windows

---

## Short version (LinkedIn headline / ATS summary)

> Windows kernel-assisted NIDS built on a six-language hub-and-spoke runtime (Zig/Go/Rust/C++/Python/TypeScript). Canonical event pipeline, 23 detection rules, hash-chained forensics, and a strict detection-only authority boundary. v1.1 shipped signed and soak-tested; real Windows E5 lab proof with negative controls.

---

## Role-specific variants

Use only bullets you can personally explain in an interview. Keep 4–6 bullets per application.

### Network Security Engineer

- Developed a Windows-native network monitoring system integrating Npcap packet capture with kernel-assisted WFP telemetry.
- Implemented a network event pipeline covering packet ingestion, normalization, rule matching, and correlation.
- Integrated multiple acquisition sources into one Zig-owned runtime through length-prefixed named-pipe contracts.
- Built detection workflows for bounded network behaviors such as TCP SYN bursts, with a negative control.
- Produced operator tooling for runtime health, event review, and forensic record verification.

**Technologies:** Windows, TCP/IP, WFP, Npcap, Go, Zig, detection-only NIDS.

### SOC / Detection Engineer

- Developed a Windows-based detection platform for network and host telemetry with one canonical event schema.
- Implemented rule matching across 23 rules spanning L4, L7, kernel file/process, and pipe families.
- Produced forensic records with traceable event/rule/audit identifiers and hash-chain integrity verification.
- Validated detection behavior with synthetic fixtures and controlled lab traffic; documented evidence levels honestly.
- Built operator views for security events, runtime health, detection results, and forensic evidence.

**Technologies:** Python, Zig, Go, Windows, detection engineering, digital forensics.

### Security Engineer / platform

- Designed security boundaries separating telemetry acquisition, detection, policy assessment, and privileged host operations.
- Enforced a single runtime owner with authenticated control-plane access; operator interfaces cannot create runtime authority.
- Fixed the fail-closed boundary so a policy `BLOCK` label is evidence of intent, never a confirmed host effect.
- Established machine-readable truth maps and release gates regenerated and verified against the build source commit.
- Shipped a signed release with verified artifacts, a 36.52 h soak PASS, and zero-loss counters.

**Technologies:** security architecture, IPC boundaries, Rust PEP, Ed25519 signing, fail-closed design.
