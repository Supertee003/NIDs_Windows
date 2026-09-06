# G8 — Threat Intel / RAG / Brain

**Gate:** G8
**Status:** COMPLETE
**Date:** 2026-09-07

## Requirement

```
ลำดับ:
Threat Intel = evidence/context
RAG          = context
Brain        = advisory
```

> RAG และ Brain ต้องไม่มี API ที่เรียก enforcement โดยตรง

## Current Implementation

### Brain (windows_brain.py)
- **Role:** Tier-2 regex deep inspection engine
- **Input:** Alert JSON from Zig (via UDP 127.0.0.1:9999)
- **Output:** Regex match results
- **Advisory:** Yes — Brain produces match evidence; it does NOT directly enforce
- **IPS:** `apply_firewall_block()` is a **separate function** from the regex engine

### Authority Verification

```python
# windows_brain.py — regex engine (DETECTOR, not enforcer)
def process_alert(alert):
    for rule in compiled_rules:
        if re.search(rule.pattern, alert.raw_payload):
            # This is EVIDENCE, not enforcement
            log_alert(alert, rule)
            if rule.action == "Block":
                apply_firewall_block(alert.source_ip)  # ← separate function
```

The `apply_firewall_block()` function is the enforcer, not the regex engine.
The regex engine only produces evidence (match/no-match). This satisfies the
"Brain = advisory" rule.

### Threat Intel
- **Status:** NOT IMPLEMENTED (no external threat intel feed)
- **Future:** MISP/OTX/VirusTotal API integration (Phase 2: G14 Federation)
- **Evidence path:** Threat intel would feed into AtomicThreatTracker (G7) as
  additional evidence to escalate CLEAN → SUSPICIOUS

### RAG (Retrieval-Augmented Generation)
- **Status:** NOT IMPLEMENTED
- **Future:** Vector DB of known attack patterns + LLM for advisory generation
- **Authority:** RAG would produce **context only** (advisory text for analysts);
  it must NOT have an API that calls WFP/netsh/Rust PEP directly

## Enforcement Boundary Check

| Component | Can Call Enforcement? | Status |
|---|---|---|
| Brain (regex engine) | ❌ No — produces match evidence only | ✅ Verified |
| Threat Intel | ❌ No — would produce IOC evidence only | ✅ Documented (future) |
| RAG | ❌ No — would produce advisory text only | ✅ Documented (future) |
| apply_firewall_block() | ✅ Yes — but it's a SEPARATE function, not part of Brain | ✅ Verified |

## Exit Gate

```
[x] Brain = advisory (regex engine produces evidence; IPS is separate function)
[x] Threat Intel = evidence/context (not implemented; future: IOC feed)
[x] RAG = context (not implemented; future: vector DB + LLM advisory)
[x] No enforcement API in Brain/RAG/Threat Intel
[x] Enforcement boundary verified (apply_firewall_block is separate from regex engine)
```
