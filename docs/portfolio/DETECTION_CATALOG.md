# Detection Rule Catalog — 23 rules, with honest evidence levels

> Source: [`configs/Rules.json`](../../configs/Rules.json), live daemon `rules` snapshot, and the
> authoritative coverage matrix
> [`analysis/current-head/RULE-COVERAGE-001-MATRIX.md`](../../analysis/current-head/RULE-COVERAGE-001-MATRIX.md).
> **An `action` of `Block` or `Drop` is a policy *intent* only.** This product cannot create a host
> block; such decisions are recorded as `observed` with `host_effect_confirmed=false`.

> **Provenance (P5-DETECTION-TRUTH).** The rule matrix and E5/E6 rows below were measured at build
> source `f4cde3c`; the immutable release identity is `a53eda8`; the current build source is
> `03bb86d`. The intervening delta is recorded as additive control-plane/observability work, but
> the matrix has **not** been re-measured at `03bb86d`. Treat every E5/E6 row here as HISTORICAL at
> its recorded source, not as current-source verification. See `docs/DETECTION_VALIDATION.md`.

## 1. Three different meanings of "coverage"

The coverage matrix deliberately separates these claims:

| Term | Meaning | Current value |
|---|---|---|
| **Catalog coverage** | rule ID in the canonical catalog with `match_pattern` + `regex_pattern`, a fixture vector, and one shared rule-ID hash | **23/23** |
| **Code-path coverage** | a production code path exists that can evaluate the rule | **23/23** |
| **Host-evaluable coverage** | the runtime can evaluate the rule from evidence it can actually receive on the measured host | **22/23** — R2003 blocked by FN-1 |
| **Host-positive proof** | the rule fired on the installed host against a real positive stimulus | **L4 family only; not 23/23** |

FN-1 means R2003's `CommandLine` field has no producer on the measured host, so it does not
satisfy "evidence it can actually receive". A rule may have a complete code path yet remain
unevaluable on this host; that is recorded as a limitation, never as a pass.

## 2. Rule matrix

Evidence key: **E1** static inspection · **E2** unit/fixture proof · **E5** Windows host observation ·
**E6** controlled lab exercise.

### L4 — network transport (3 rules)

| ID | Name | Severity | Action | Detection logic | Evidence |
|---|---|---|---|---|---|
| **R9002** | ICMP Flood (DoS) | High | Drop | `PROTO:ICMP`, rate `count ≥ 50` in 1000 ms | **E5** rate lab 15/15 |
| **R9006** | TCP SYN Stealth Scan | Medium | Alert | `FLAGS:S`, rate `distinct_dst_ports ≥ 20` in 10,000 ms | **E5 + E6**: ≥20-port burst, 118,632-row zero-FP control, plus the recorded demo burst |
| **R9007** | TCP XMAS Scan | Medium | Alert | `FLAGS:FPU` pattern | **E5** rate lab |

**Boundary:** exact TCP-flag predicates evaluate on outbound WFP only; inbound WFP carries no flags
evidence (sidecar 0). Npcap/Nose provide flags on both directions.

### L7 — application-layer patterns (5 rules)

| ID | Name | Severity | Action | Detection logic | Evidence |
|---|---|---|---|---|---|
| **R0056** | SQL Injection (Auth Bypass) | Critical | Drop | `' OR 1=1`, fast pattern `SQLI_BYPASS`, TCP/80,443,8080,3306,8443 | E1/E2 synthetic — LIM-1 |
| **R9064** | OS Command Injection (Semicolon) | Critical | Drop | `;whoami`, fast pattern `OSI_SEMI` | E1/E2 synthetic — LIM-1 |
| **R9059** | Cross-Site Scripting (Basic) | High | Alert | `<script>`, `alert(`, `onerror=` | **E5 wire** |
| **R0088** | Path Traversal (Sensitive) | Critical | Block | `../../etc/passwd`, `..\..\`, `win.ini` | **E5 wire** |
| **R0089** | Remote File Inclusion (RFI) | Critical | Block | `?file=http://`, `include=https://` | E1/E2 synthetic — LIM-1 |

**LIM-1:** a network AC hit is only possible for **plaintext bytes present in the first 4096 bytes
of a single packet**. There is no TCP reassembly and TLS bodies remain ciphertext. No proxy/app
sensor feeds these rules. Absence of a hit is not absence of the content.
`event_processor.zig:423` gates L7 protocol-anomaly extraction to `.capture_npcap` only.

### KERNEL_FILE — host file telemetry (5 rules)

| ID | Name | Severity | Action | Detection logic | Evidence |
|---|---|---|---|---|---|
| **R1001** | System32 Write Attempt | Critical | Block | `C:\Windows\System32` path pattern | E1/E2 synthetic |
| **R1002** | Ransomware Rename Pattern | Critical | Drop | `.locked`, `.encrypted`, `.cryptolocker`, `.ransom` | E1/E2 synthetic; **E5 canary** in RULE-LAYER-SCOPE-001 |
| **R1003** | Startup Folder Modification | High | Block | `Startup`, `Start Menu\Programs\Startup` | E1/E2 synthetic |
| **R1004** | DLL Drop in System32 | Critical | Drop | `.dll`, `DLL_DROP` | E1/E2 synthetic |
| **R1005** | hosts File Modification | High | Block | `hosts` / `drivers\etc\hosts` path | E1/E2 synthetic |

### KERNEL_PROCESS — host process telemetry (5 rules)

| ID | Name | Severity | Action | Detection logic | Evidence |
|---|---|---|---|---|---|
| **R2001** | Mimikatz Execution | Critical | Drop | `mimikatz`, `sekurlsa::logonpasswords` | E1/E2 synthetic |
| **R2002** | svchost Process Hollowing | Critical | Drop | `svchost.exe`, `PROCESS_HOLLOW` | E1/E2 synthetic |
| **R2003** | PowerShell Cradle Download | Critical | Block | `IEX`, `DownloadString`, `Net.WebClient` | E1/E2 synthetic — **FN-1 OPEN** |
| **R2004** | certutil Download Abuse | High | Block | `certutil -urlcache -f` | E1/E2 synthetic; earlier live proof in RULE-LAYER-SCOPE-001 |
| **R2005** | procdump Credential Harvest | Critical | Drop | `procdump`, `lsass.exe` | E1/E2 synthetic |

**FN-1 (accepted limitation):** on the measured host, process telemetry v0–v4 carries **no
`CommandLine`** field, and a real command-line source is not implemented in this build. R2003 is
therefore inert on host process rows. The Zig consumer can decode a `CommandLine` TLV if a future
provider supplies one, but no positive host proof exists here. Do not manufacture one.

### L2_PIPE — named-pipe telemetry (5 rules)

| ID | Name | Severity | Action | Detection logic | Evidence |
|---|---|---|---|---|---|
| **R3001** | Cobalt Strike Named Pipe | Critical | Drop | `MSSE-`, `postex_`, `status_` | E1/E2 synthetic |
| **R3002** | PsExec Remote Execution | High | Block | `psexec`, `\pipe\PAExec` | E1/E2 synthetic |
| **R3003** | Anonymous Pipe Suspicious | Medium | Alert | `anonymous`, `\pipe\anonymous` | E1/E2 synthetic; **E5 ambient negative observation** |
| **R3004** | Meterpreter Named Pipe | Critical | Drop | `meterpreter`, `\pipe\meterpreter` | E1/E2 synthetic |
| **R3005** | atexec Scheduled Task Pipe | High | Block | `atsvc`, `\pipe\atsvc` | E1/E2 synthetic |

## 3. Who actually decides

- **Zig** builds an Aho-Corasick automaton from `match_pattern` in exactly one place and is the
  sole detection-verdict authority. It never compiles `regex_pattern`.
- **Python Brain (Tier-2 analytics)** owns `regex_pattern`; it is advisory, not a verdict.
- **Go Nose** owns no rule file, matcher, or verdict; acquisition-authored verdicts are stripped at
  Zig ingress (`ingress_authority.claims_stripped`).
- The rule-ID hash is **FNV-1a** over the rule-id string, pinned across Python, Zig, and CLI by
  `tests/security/test_detection_contract_pin.py`.
- Network automaton membership is layer-filtered: kernel process patterns cannot match wire bytes
  (the FP-1 fix). Rules validate command checks required fields only — it does **not** compile
  regexes or prove efficacy.

## 4. MITRE ATT&CK

**There is no reviewed, authoritative MITRE ATT&CK mapping in this repository.** `configs/Rules.json`
and `docs/DETECTION_VALIDATION.md` contain no technique IDs. The IDs that do exist are comments in
the NOT-WIRED injection detector (`src/detection/injection_detector.zig`, T1055 and sub-techniques)
and a test-only scenario library named in `docs/ARCHITECTURE.md`; neither is a mapping deliverable.
Do not present a technique mapping as a project deliverable until one is written against the real
detection logic and reviewed.

## 5. The one demo that has a full evidence chain

A bounded 40-SYN burst from `192.168.1.39` to `192.0.2.1:1–40` during a `lab_attack_window`
measurement produced `VERDICT: PASS (exit 0)`, one attributed row, and **one R9006** detection,
with drop/shed/quota deltas all `0`. See [Demo](DEMO.md) and
`admin-evidence/lab-director-demo-20261123/attack-window-20261123T133909Z.json`.

---

*See also: [Canonical event schema](../CANONICAL_EVENT_SCHEMA.md) ·
[Test results](../testing/RESULTS.md) · [Security boundaries](../architecture/SECURITY_BOUNDARIES.md)*
