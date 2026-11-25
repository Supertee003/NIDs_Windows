# Current detection matrix — 23 rules (`7822f4c` records projection)

> Generated from `configs/Rules.json` (catalog identity, layer, severity, action, `match_pattern`)
> and `docs/DETECTION_VALIDATION.md` (fixture, qualification, proof, E-level). No status is invented.
> This is a **records projection**, not a fresh build/host run and not a second specification.
> The current build source is `7822f4c`. The rule matrix and its E5/E6 rows were last measured at
> `f4cde3c`; the immutable release identity is `a53eda8`. The earlier `a26c573` and `43a8bcc`
> sources are HISTORICAL; the matrix has **not** been re-measured at `7822f4c`. E3/E4/E5 proof at
> `43a8bcc` is HISTORICAL and covers the narrow `-inject` lifecycle only; E3 at `7822f4c` is
> current for that narrow pipe-reader lifecycle only, and E4/E5 at `7822f4c` are NOT_PROVEN
> until owner-run elevated re-proof.
>

**Action** below is policy intent. Production is observe-only: `prevention_gate=closed`,
`host_effect_capable=false`; `Block`/`Drop` never claims a host effect.

## Coverage counts (not interchangeable)

| Term | Value | Boundary |
|---|---|---|
| Catalog coverage | 23/23 | `rule_id`, `match_pattern`, `regex_pattern`, fixture, shared hash |
| Code-path coverage | 23/23 | Zig evaluates `match_pattern`; Python `regex_pattern` is advisory |
| Host-evaluable coverage | 22/23 | R2003 blocked by FN-1 |
| Host-positive proof | L4 family only; strongest R9006 | HISTORICAL @ `f4cde3c`, not current-source |

## Per-rule matrix

| ID | Catalog name | Layer | Sev | Action (intent) | `match_pattern` | Fixture | Validation proof | Current-source status @ `7822f4c` | Limitation |
|---|---|---|---|---|---|---|---|---|---|
| **R0056** | SQL Injection (Auth Bypass) | L7 | Critical | Drop | `' OR 1=1` | FX-01 | SYN / E1 | code-path/fixture only @ `7822f4c`; not host-positive | LIM-1: plaintext first 4096 bytes only |
| **R9064** | OS Command Injection (Semicolon) | L7 | Critical | Drop | `;whoami` | FX-02 | SYN / E1 | code-path/fixture only @ `7822f4c`; not host-positive | LIM-1: plaintext first 4096 bytes only |
| **R9059** | Cross-Site Scripting (Basic) | L7 | High | Alert | `<script>` | FX-03 | SYN / E1 | code-path/fixture only @ `7822f4c`; not host-positive | LIM-1: plaintext first 4096 bytes only |
| **R0088** | Path Traversal (Sensitive) | L7 | Critical | Block | `/etc/passwd` | FX-04 | SYN / E1 | code-path/fixture only @ `7822f4c`; not host-positive | LIM-1: plaintext first 4096 bytes only |
| **R9002** | ICMP Flood (DoS) | L4 | High | Drop | `PROTO:ICMP` | FX-05 | SYN + LAB (rate lab, 15/15 boundaries) / E1 + E5 | HISTORICAL @ `f4cde3c`; **not re-measured** @ `7822f4c` | — |
| **R9006** | TCP SYN Stealth Scan | L4 | Medium | Alert | `FLAGS:S` | FX-06 | SYN + **LAB real ≥20-port burst**, 118,632 ordinary rows → 0 false hits + SIM 150-connect scan / E1 + **E5 + E6** | HISTORICAL @ `f4cde3c`; **not re-measured** @ `7822f4c` | — |
| **R9007** | TCP XMAS Scan | L4 | Medium | Alert | `FLAGS:FPU` | FX-07 | SYN + LAB (rate lab) / E1 + E5 | HISTORICAL @ `f4cde3c`; **not re-measured** @ `7822f4c` | — |
| **R1001** | System32 Write Attempt | KERNEL_FILE | Critical | Block | `C:\Windows\System32` | FX-08 | SYN / E1 | code-path/fixture only @ `7822f4c`; not host-positive | — |
| **R1002** | Ransomware Rename Pattern | KERNEL_FILE | Critical | Drop | `.locked` | FX-09 | SYN / E1 | code-path/fixture only @ `7822f4c`; not host-positive | — |
| **R1003** | Startup Folder Modification | KERNEL_FILE | High | Block | `Startup` | FX-10 | SYN / E1 | code-path/fixture only @ `7822f4c`; not host-positive | — |
| **R1004** | DLL Drop in System32 | KERNEL_FILE | Critical | Drop | `.dll` | FX-11 | SYN / E1 | code-path/fixture only @ `7822f4c`; not host-positive | — |
| **R1005** | hosts File Modification | KERNEL_FILE | High | Block | `hosts` | FX-12 | SYN / E1 | code-path/fixture only @ `7822f4c`; not host-positive | — |
| **R2001** | Mimikatz Execution | KERNEL_PROCESS | Critical | Drop | `mimikatz` | FX-13 | SYN / E1 | code-path/fixture only @ `7822f4c`; not host-positive | — |
| **R2002** | svchost Process Hollowing | KERNEL_PROCESS | Critical | Drop | `svchost.exe` | FX-14 | SYN / E1 | code-path/fixture only @ `7822f4c`; not host-positive | — |
| **R2003** | PowerShell Cradle Download | KERNEL_PROCESS | Critical | Block | `IEX` | FX-15 | SYN; **FP-1 CLOSED at E5, FN-1 OPEN** (§5) / E1 | code-path/fixture only @ `7822f4c`; FN-1 OPEN | FN-1: no `CommandLine` producer |
| **R2004** | certutil Download Abuse | KERNEL_PROCESS | High | Block | `certutil` | FX-16 | SYN / E1 | code-path/fixture only @ `7822f4c`; not host-positive | — |
| **R2005** | procdump Credential Harvest | KERNEL_PROCESS | Critical | Drop | `procdump` | FX-17 | SYN / E1 | code-path/fixture only @ `7822f4c`; not host-positive | — |
| **R3001** | Cobalt Strike Named Pipe | L2_PIPE | Critical | Drop | `MSSE-` | FX-18 | SYN / E1 | code-path/fixture only @ `7822f4c`; not host-positive | — |
| **R3002** | PsExec Remote Execution | L2_PIPE | High | Block | `psexec` | FX-19 | SYN / E1 | code-path/fixture only @ `7822f4c`; not host-positive | — |
| **R3003** | Anonymous Pipe Suspicious | L2_PIPE | Medium | Alert | `anonymous` | FX-20 | SYN / E1 | code-path/fixture only @ `7822f4c`; not host-positive | — |
| **R3004** | Meterpreter Named Pipe | L2_PIPE | Critical | Drop | `meterpreter` | FX-21 | SYN / E1 | code-path/fixture only @ `7822f4c`; not host-positive | — |
| **R3005** | atexec Scheduled Task Pipe | L2_PIPE | High | Block | `atsvc` | FX-22 | SYN / E1 | code-path/fixture only @ `7822f4c`; not host-positive | — |
| **R0089** | Remote File Inclusion (RFI) | L7 | Critical | Block | `?file=http://` | FX-23 | SYN / E1 | code-path/fixture only @ `7822f4c`; not host-positive | LIM-1: plaintext first 4096 bytes only |

## How to read this table

- `Validation proof` is copied from `docs/DETECTION_VALIDATION.md`; it is not re-derived here.
- `HISTORICAL @ f4cde3c` means the E5/E6 row belongs to that recorded source, not to `7822f4c`.
- `code-path/fixture only` means E1/E2 evidence; it never closes a live-detection gate.
- FN-1 and LIM-1 are accepted limitations. No rule is marked proven while its limitation is open.
- The catalog's extra boundary notes (R1002 canary, R3003 ambient negative, R9006 inbound-WFP
  flags, FP-1 closure) remain in `docs/portfolio/DETECTION_CATALOG.md`.

## Do not infer

- Do not merge the 23/23 catalog count with the 22/23 host-evaluable count.
- Do not promote the narrow `43a8bcc` `-inject` E4/E5 proof (HISTORICAL at that source) to
  detection-matrix, soak or E6/E7 proof at `7822f4c`.
- Do not convert `Block`/`Drop` into a host-effect claim or a MITRE ATT&CK mapping.

---

Sources: [`configs/Rules.json`](../../configs/Rules.json) ·
[`docs/DETECTION_VALIDATION.md`](../DETECTION_VALIDATION.md) ·
[`docs/portfolio/DETECTION_CATALOG.md`](DETECTION_CATALOG.md) ·
[`docs/evidence/PROVENANCE.md`](../evidence/PROVENANCE.md)
