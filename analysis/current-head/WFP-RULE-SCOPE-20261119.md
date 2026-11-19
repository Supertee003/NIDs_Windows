# WFP rule scope — what a kernel-captured row can and cannot prove

**DATE:** 2026-11-19
**PATCH-ID:** VISIBILITY-001 (Slice 2, items 3-4)
**EVIDENCE LEVEL:** E1 (current-source inspection). E5 host proof pending.

This document closes the two remaining Slice 2 items: state the WFP sensor's
boundaries as **rule-scope constraints**, so a rule that cannot be evaluated
from kernel evidence is never silently reported as "covered".

---

## 1. What the kernel provider actually delivers

Source of truth: `drivers/wfp_callout/aegis_wfp.h`, `aegis_wfp_callout.c`,
`src/capture/wfp_telemetry.zig`, `src/policy/wfp_ioctl.zig`.

| Property | Value | Consequence |
|---|---|---|
| Transport payload copy | `AEGIS_MAX_PAYLOAD_SIZE = 4096` bytes, `payload_length` claims the exact length (0 = empty/unavailable/unsupported, explicitly labeled) | L7 patterns beyond the first 4096 bytes of a packet are **not observable** |
| Reassembly | **none** — one callout copy per packet | A pattern split across TCP segments cannot match, regardless of total stream length |
| Encryption | copy is taken at the transport layer; TLS/HTTPS bodies remain **ciphertext** | No application-layer regex/AC hit on an encrypted body — absence of a hit is not absence of the content |
| Direction | real kernel direction byte | outbound rows carry TCP flags metadata; **inbound WFP has no flags evidence** (sidecar 0) |
| Interfaces | every interface incl. tunnels (unlike a pinned Npcap adapter) | wider L4 visibility, same payload limits |
| Identity sidecar (v6 rows) | 32 bytes consumed from the same 4096-byte budget | effective body budget shrinks to 4064 bytes when bit0 is set |

`payload_length >= 32` with bit0 set is a fail-closed contract guard; the
callout shrinks `copyLen` so its own records can never trip it.

---

## 2. Rule-layer evaluability on a WFP row

`ruleLayerIndexForSource()` maps `.capture_wfp` to the **network** layer, exactly
like `.capture_npcap`. `resolveRuleAutomaton()` therefore runs the network AC on
the bounded payload when `payload_len > 0`.

| Layer | Evaluable from WFP? | Notes |
|---|---|---|
| **L4** (`R9002`, `R9006`, `R9007`) | **yes** | protocol / ports / rate evaluate on every network source. Exact TCP flags evaluate on **outbound** WFP only (RULE-COVERAGE-001); inbound leaves the sidecar at 0 and a flags-specific predicate cannot match zero-filled evidence. |
| **L7 network AC** (`R0056`, `R0088`, `R0089`, `R9059`, `R9064`) | **conditionally** | only for plaintext bytes present in the first ≤4096 bytes of a single packet. Split patterns, later bytes and ciphertext are outside the sensor. This is a sensor boundary, not a detector defect. |
| **L7 observe-only protocol anomalies** | **no** | `event_processor.zig:423` gates `l7_payload.extractEthernet` on `.capture_npcap` only. WFP rows do not produce protocol-anomaly evidence. |
| **KERNEL_FILE / KERNEL_PROCESS / L2_PIPE** (`R1xxx`, `R2xxx`, `R3xxx`) | **no, by design** | FP-1 fix: wire sources only ever consult the network automaton; a kernel-process pattern can never match wire bytes. Process/file/pipe rules need their own host sensors. |

---

## 3. Honest coverage statement

For the 23-rule catalog (`RULE-COVERAGE-001-MATRIX.md`):

- **Catalog coverage 23/23** — every rule has both fields, a fixture vector and
  one shared rule-id hash.
- **Evaluable coverage 23/23** — each rule has a production runtime path from
  *some* supported evidence source. After RULE-COVERAGE-001, L4 rules are no
  longer Npcap-only.
- **Per-source coverage is narrower and is now explicit** — `kernel_primary`
  ingress is stronger for L4 visibility on all interfaces but weaker for L7
  content (no reassembly, ≤4096 B, no encrypted bodies, no protocol-anomaly
  extraction). That is why the default remains `npcap_primary` and why
  `AEGIS_CAPTURE_PRIMARY=kernel` is an explicit operator choice rather than an
  automatic failover.

No rule may be claimed "verified on WFP" from this document. The E5 evidence
for the new binary must measure the actual mode and the actual rule hits;
until then these are code-level scope statements only.
