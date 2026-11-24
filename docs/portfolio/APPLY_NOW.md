# Technical evidence quick reference

This path is retained as a stable link target for existing documentation. It contains only
technical claims and current-source boundaries. Current machine-readable truth is in
`SYSTEM_MAP.json`, `FLOW_MAP.json`, `AUTHORITY_MAP.json`, `CONTRACT_MAP.json`,
`runtime_manifest.json`, `build_manifest.json` and `EVIDENCE_INDEX.json`.

## Links

| Asset | Location |
|---|---|
| Repository | https://github.com/Supertee003/NIDs_Windows |
| v1.1 release (gates, signature, soak evidence) | https://github.com/Supertee003/NIDs_Windows/releases/tag/v1.1 |
| 1-minute README (with real screenshot) | https://github.com/Supertee003/NIDs_Windows#aegis-in-60-seconds |
| 2:27 live demo (traffic → event → detection → dashboard → forensic record) | https://github.com/Supertee003/NIDs_Windows/blob/main/docs/portfolio/images/demo.mp4 |
| Architecture explained in English | https://github.com/Supertee003/NIDs_Windows/blob/main/docs/portfolio/ARCHITECTURE_EN.md |
| Project summary | https://github.com/Supertee003/NIDs_Windows/blob/main/docs/portfolio/RESUME_PROJECT.md |
| Demo script / chapter guide | https://github.com/Supertee003/NIDs_Windows/blob/main/docs/portfolio/DEMO.md |
| Scope and status table (IDS vs IPS, one answer) | https://github.com/Supertee003/NIDs_Windows#scope-and-status-in-one-table |
| Detection rule catalog | https://github.com/Supertee003/NIDs_Windows/blob/main/docs/portfolio/DETECTION_CATALOG.md |
| Security threat model | https://github.com/Supertee003/NIDs_Windows/blob/main/docs/SECURITY_THREAT_MODEL.md |
| Source-level technical Q&A | https://github.com/Supertee003/NIDs_Windows/blob/main/docs/portfolio/INTERVIEW_PREP.md |

---

## One-paragraph technical summary

AEGIS NIDS Windows is a Windows-native, kernel-assisted network intrusion detection system.
It turns real packet and host telemetry into one canonical event, runs 23 detection rules, and
writes hash-chained forensic evidence with an evidence receipt. The engineering challenge is
authority: the runtime spans Zig, Go, Rust, C/C++, Python and TypeScript (six language families,
seven toolchains; C/C++ is one adapter family; TypeScript is advisory-only), but one Zig runtime
owns the pipeline and no layer can promote "detected" into "blocked." Published `v1.1` is an
Ed25519-signed, detection-only build from signed candidate `466a226` / build source `a53eda8`,
with a genuine 36.52 h owner-run soak PASS and a bounded Windows host detection proof that has a
negative control. Current build source is `e406cbb`; no current-source E5/soak result is claimed.

---

## Technical Q&A

1. **"Isn't this just an IDS with rules?"** — The hard part is not the regex; it is the authority
   model. One canonical event schema has byte-exact codecs in Zig, Go, C and Python plus a golden
   tuple map; Rust has no production codec (TBD). One Zig runtime owns the pipeline, and the Rust
   PEP is a detection-only policy/evidence authority. Steps that might mutate a host exist only in
   a separately compiled lab gate; production cannot open the prevention gate.

2. **"How do you know detection works?"** — Real Windows E5 lab proof was recorded at historical
   build sources: a bounded SYN burst was attributed by exact 5-tuple to R9006 with a 10-port
   negative control that produced zero hits; a bridged-Kali window attributed multiple rules with
   no drop/shed/quota deltas. All 23 rules have synthetic fixtures, but code-path 23/23 and
   host-evaluable 22/23 are different claims; R2003 is blocked by FN-1. Live proof is strongest on
   L4. See `DETECTION_CATALOG.md` and `docs/DETECTION_VALIDATION.md` for provenance.

3. **"Did it actually block anything?"** — No. That is by design. A `BLOCK` label is intent;
   only a receipt with a verified host postcondition could claim a block, and this build cannot
   produce one. Block/quarantine decisions are reported as ESCALATE reason 8 with `filter_id=0`
   and `host_effect_confirmed=false`.

---

## Claims guardrail

Never say: IPS, blocks traffic in production, EV/HLK signed driver, Microsoft attestation,
Signed-IR promotion, production fleet deployment, all 23 detections live-proven, replay
re-executes detection, "zero loss ever," fake E5/soak PASS, re-key, invented MITRE mapping,
benchmark ceiling, or production-ready.

Say: **Windows kernel-assisted NIDS, detection-only, real evidence, fail-closed, honest
DEGRADED state.**

See [Architecture](ARCHITECTURE_EN.md) and [Project summary](RESUME_PROJECT.md) for the full facts.
