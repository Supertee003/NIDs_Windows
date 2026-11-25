# Case study — engineering decisions and results (honest portfolio view)

> Scope: build source `4dd3393`. AEGIS-PLAN-020.
> Every result below names its evidence source. Historical numbers are not
> presented as a current run.

## 1. Problem

Build a Windows NIDS where no component can authorize a host effect, while
keeping a single canonical event schema across Zig, Go, C++, and Python and an
advisory TypeScript policy plane. The hard part is not detection logic; it is
keeping authority, truth, and evidence from drifting apart as the system grows.

## 2. Decisions

| Decision | Why | Where it is pinned |
|---|---|---|
| One detection-policy authority, no host-effect authority | Rust PEP evaluates policy and emits evidence; no component mutates WFP | `AUTHORITY_MAP.json`, RETIRE-HOST-EFFECT-001 / issue #25, `AI_CONTEXT.md` |
| Records carry build source, not records HEAD | A records-only commit must not invalidate a source-pinned map | ADR-0008, `tools/truth.py verify` |
| One schema, N codecs | Wire changes must update all codecs plus the golden vector in the same patch | `AGENTS.md` test hygiene, `shared/protocol/wire_v2.md` |
| Lossy bounded queue with counted shedding | Fairness between host sensors; blocking one lane can blind another | ADR-0010, ADR-0012, ADR-0014, `docs/runtime/QUEUE_SEMANTICS.md` |
| Bounded IPv6 extension walk and tracked capture gaps | Avoid unbounded parser work while preserving visibility | C6 slice `7822f4c`, `docs/portfolio/SENSOR_COVERAGE.md` |
| Versioned canonical policy bytes, additive only | Cross-language byte equality without changing legacy policy hashes/signatures | S4 `2673bd2` / seam `4dd3393` |
| Additive source slices S1–S4 at E2 | Each closes a source gap without pretending to have a host run | `EVIDENCE_INDEX.json` entries `493648f`, `4bc8244`, `f1f89c1`, `2673bd2` |

## 3. Results (with level)

| Result | Level and commit |
|---|---|
| Truth maps valid at build source | `TRUTH_VALID @ 4dd3393` |
| Artifact digests | 690 artifacts match recorded digests |
| Document/release gates | 262 passed at S4 source |
| Full non-host suite | 1,502 passed, 1 skipped, 18 deselected, 27 subtests passed at S4 source |
| Evidence level E2 count | 165 after S4 entry |
| Immutable release identity | `v1.1` / `466a226` / `a53eda8`, 6/6 gates PASS at that identity only |
| Narrow `-inject` E3/E4/E5 | `7822f4c`, exact deltas and verified host restore; HISTORICAL at `4dd3393` |
| Canonical policy bytes | Four-language byte equality E2 at `2673bd2` / `4dd3393` |

## 4. Results deliberately not claimed

- No current-head full Windows E5 or kernel IDS qualification.
- No detection matrix re-measurement at `4dd3393` (last measured `f4cde3c`).
- No controlled fixed-rate throughput ceiling.
- No new signature, key, tag, or `v2.1.0`.
- No soak re-run at current source.
- Two `host_live` integration tests remain unresolved; they are not counted as
  passing evidence.

## 5. How to read this case study

This is an engineering-decision record, not a marketing page. The strongest
verified claims are: truth coherence at a pinned source, cross-language byte
equality, additive source gaps closed at E2, and honest limitation tracking.
Physical host proof remains an owner-run activity documented in
`analysis/current-head/OWNER-RUN-HOST-PROOF-RUNBOOK-20261126.md`.

---

See also: [`ARCHITECTURE_EN.md`](ARCHITECTURE_EN.md),
[`RESUME_PROJECT.md`](RESUME_PROJECT.md),
[`VERIFICATION_SUMMARY.md`](VERIFICATION_SUMMARY.md),
[`PERFORMANCE_REPORT.md`](PERFORMANCE_REPORT.md).
