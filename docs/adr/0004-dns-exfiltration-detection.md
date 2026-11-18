# ADR-0004: DNS Exfiltration Detection

**Status:** Proposed (blocked on rule-owner verdict + sensor proof)
**Date:** 2026-10-06

## Context

`data_exfil` (DNS tunneling) is the last quarantined canary
(`configs/canary_tests.json`): its payload (`large-dns-query.evil.com`,
25 chars — not itself length-anomalous) matches neither the
`match_pattern` (`<script>`) nor the regex of its named rule R9059
(XSS, `configs/Rules.json`), so it is reported with a reason and never
graded. RFI graduated the same way via R0089 (RFI-RULE-071); DNS-exfil
cannot follow that path. Investigation (code, not opinion):

1. Tier-1 (Go `nose/signature_classifier.go`, Zig automaton) is
   **substring-only** over `match_pattern`. Length is inexpressible
   there without a new rule-field capability.
2. Tier-2 (Brain regex) *could* express length, but in production it
   only sees detections: `brainInspect`/`siemForward` return early on
   `rule_id == 0` (`src/pipeline/event_processor.zig`). Unmatched DNS
   payloads never reach the brain; Case-2 "No Tier-1 Match" offers
   come only from the orphan `nids_analyze` path, never the daemon.
3. The correlator **does** see every event including `rule_id == 0`
   (`event_processor.zig:126-135`; IDs in the 9000 block). Rate-based
   tunneling detection has a natural home here.
4. No tier parses DNS: nose has no QNAME/53 handling, and wire-format
   QNAME is length-prefixed labels, not the dotted string a regex
   would assume. There is no DNS telemetry to hang a length rule on.
5. Objective protocol facts (RFC 1035, not tuning): label <= 63
   octets, name <= 253 octets. Anything longer is malformed, not
   merely suspicious.

## Options

- **A. Signature length rule** (`match_pattern` + length): REJECTED —
  needs a new rule-field capability in Go *and* Zig plus contract-pin
  updates, for a signal no sensor produces.
- **B. Brain regex on forwarded unmatched payloads**: REJECTED —
  needs an unmatched-forward path in the production pipeline (new
  noise surface, spool/backpressure design) for one rule family.
- **C. Correlator rate rule** (9000 block: N DNS-shaped events to a
  rare destination in window T): CANDIDATE — fits the existing
  observe-everything correlator, no wire/capability change. Needs
  tuned (N, T) + Kali proof.
- **D. DNS sensor parser + length rule**: CANDIDATE — the principled
  home for RFC-1035 violation detection, but a new sensor is its own
  slice (parser, tests, Kali proof) before any rule.

## Recommendation

C first (behavioral tunneling, no new sensor), D when a DNS sensor
slice lands. A and B stay rejected. `data_exfil` stays quarantined
until the chosen rule exists *with* sensor proof; its fixture payload
must be replaced with a genuinely anomalous signal at that point
(the current 25-char payload would not fire any length rule).

## Open owner questions

1. Rule ID, severity, action for the tunneling rule (C)? (Severity/
   action are detection-semantics calls, not derivable from the
   quarantined payload: Low/Alert mirrors the old canary label.)
2. Correlator thresholds (N events, T window, rarity definition)?
3. Kali proof plan: tunneling generator + benign-DNS baseline to
   bound false positives?
4. Is a DNS sensor parser (D) in scope, and if so, before or after C?

## Consequences

1. No DNS-exfil rule is added by this ADR; the quarantine stands.
2. Answering 1–3 unlocks the implementation slice (rule + fixture +
   canary graduation, same ripple pattern as RFI-RULE-071).
3. Answering 4 schedules the sensor slice independently of C.

## References

- `configs/canary_tests.json` (data_exfil, quarantine_reason)
- `configs/Rules.json` (R0089 precedent, R9059 mismatch)
- `src/pipeline/event_processor.zig` (correlator sees all; brain/siem
  detections-only)
- `analysis/UNWIRED_INVENTORY.md` (quarantine log)
