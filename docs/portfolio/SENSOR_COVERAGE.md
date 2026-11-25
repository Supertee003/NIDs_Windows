# Sensor coverage — capture variants and proof limits

> Scope: build source `4dd3393`. AEGIS-PLAN-008.
> This page maps what the capture path is **designed** to observe and what has
> actually been measured. Source-level support is not host proof.

## 1. Coverage matrix

| Variant | Source-level support at `4dd3393` | Measured proof | Status |
|---|---|---|---|
| IPv4 / TCP / UDP / ICMP | CanonicalEvent codecs in Zig/Go/C++/Python, shared `event_v*` vectors | E2 vector equality; historical E5 detection rows | Coverage in code, current-source host proof NOT_PROVEN |
| IPv6 | Canonical header + IPv6 forensic ABI (ADR-0006) | E2 codec/vector tests; C6 narrow `-inject` E3/E4/E5 at `7822f4c` | Current-source host proof NOT_PROVEN |
| IPv6 extension headers | Bounded extension walk in C6 capture slice (`7822f4c`) | E2 at `7822f4c`; **HISTORICAL** at `4dd3393` | Source support exists in ancestry, not re-measured at current source |
| VLAN / QinQ | C6 capture visibility slice (`7822f4c`) | E2 at `7822f4c`; narrow E3/E4/E5 at `7822f4c` | Current-source host proof NOT_PROVEN |
| Truncated / malformed frame | Length-aware envelope; reject/trailing/oversize tests in `tests/contracts/` | E2 (`test_payload_envelope_v3.py`, `test_ipv6_wire_v2.py`) | E2 PASS at `4dd3393` |
| Embedded NUL / invalid UTF-8 binary payload | Length-aware codecs; no `str(payload)` detector semantics | E2 contract tests | E2 PASS at `4dd3393` |
| R2003 process command-line producer | S1 source slice `493648f` | E2 producer test | Host R2003 E5 requires owner run; NOT_PROVEN |
| Kernel minifilter ring | Admission design in ADR-0010/0014 | Historical E5 window with ring drops 0 | Current-source E5 NOT_PROVEN |

## 2. Why the columns are separate

- **Source-level support** means a codec, parser, or producer exists and has a
  unit/vector test at the listed source commit.
- **Measured proof** means an artifact exists at a stated evidence level and
  commit. It is never promoted across commits.
- `7822f4c` and `43a8bcc` E3/E4/E5 records are HISTORICAL relative to
  `4dd3393`. The narrow `-inject` proof covered exact pipe-reader deltas and
  host lifecycle, **not** a full capture-path or detection-efficacy matrix.

## 3. Known acquisition gaps still open

- VLAN/QinQ and IPv6-extension visibility are source-supported but lack a
  current-source host measurement.
- Process-relative `monotonic_ns` was added in C6; no cross-source host proof.
- WFP `npcap_primary` acquisition depends on the installed host adapter; the
  repository cannot prove adapter behavior from a fresh clone.
- Full Windows E5 / kernel IDS qualification is **NOT_PROVEN** at `4dd3393`.

## 4. Owner actions

Run the capture and R2003 sections of
`analysis/current-head/OWNER-RUN-HOST-PROOF-RUNBOOK-20261126.md`, record the
installed binary SHA-256 and build source, and only then promote any row above
to E5. Negative controls must be part of the same run.

---

See also: [`DETECTION_MATRIX_CURRENT.md`](DETECTION_MATRIX_CURRENT.md),
[`VERIFICATION_SUMMARY.md`](VERIFICATION_SUMMARY.md),
[`../evidence/PROVENANCE.md`](../evidence/PROVENANCE.md).
