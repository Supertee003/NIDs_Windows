# ADR-0009: Kernel IDS Integrity Plane Reuses IPS Safety Invariants

**Status:** Accepted for the IDS direction reset  
**Date:** 2026-10-31  
**Scope:** Production kernel-level intrusion detection; IPS remains lab/qualification-only

## Patch decision

The project will reuse the strongest safety mechanisms developed for IPS—single authority, validation, gates, receipts, postconditions, rollback, two-person approval, and audit—in the kernel IDS path as **integrity controls**. It will not import host mutation into the production IDS runtime.

## Context

The repository contains mature IPS safety mechanisms: Rust PEP authorization, receipt-gated WFP effects, prevention gates, provider read-back, action dispatch, canary ordering, rollback, and operator approval. The production objective has now been clarified as kernel-level NIDS. Directly connecting those IPS paths to sensors or detectors would violate separation of concerns and create duplicate enforcement authority.

The useful design question is therefore not “how does IDS block?” but “how does IDS prove that a detection is trustworthy, attributable, reproducible, and safely recorded?”

## Decision

### 1. Three authorities remain distinct

- **Detection Authority:** Zig Runtime Spine owns detector orchestration, correlation, and the detection verdict. Sensors only acquire and normalize observations.
- **Evidence Authority:** the forensic pipeline owns the immutable, hash-chained account of the observation, detector result, correlation, policy observation, and any advisory output.
- **Enforcement Authority:** Rust PEP remains the only authority allowed to approve a privileged host effect. It is outside the production IDS detection decision and is not called by a sensor or detector directly.

No module may combine these authorities merely for convenience.

### 2. IPS mechanisms are translated into IDS integrity controls

| IPS mechanism | IDS use | Prohibited transfer |
|---|---|---|
| PEP single authority | one evidence-only policy evaluation authority | detector cannot become a host-effect authority |
| request validation | validate event shape, source, timestamps, payload bounds, rule provenance | do not mutate host state on validation failure |
| prevention gate | detection-source readiness and capability gates | never turn a sensor-ready flag into a host-effect gate |
| provider receipt | immutable detection/evidence receipt tying source, detector, event ID, rule, and result | never call it proof of host enforcement |
| provider postcondition | verify that evidence was persisted and replay/verifier can read it | never claim WFP state from an IDS receipt |
| rollback | bounded suppression/reconfiguration rollback for detector configuration | never use rollback to undo host state from an IDS path |
| two-person approval | approval for detector rule/config promotion and production enablement | never approve direct detector-to-WFP calls |
| canary ordering | scope → target → expiry → rollback → audit for new sensors/detectors | do not use IPS canary code in the production daemon |
| audit trail | record provenance, decision trace, and evidence hash | no untraceable advisory output |

### 3. Define an IDS Evidence Receipt

An IDS Evidence Receipt is an immutable, non-enforcement acknowledgement emitted only after the evidence writer accepts a detection record. It binds:

- source identity and route (`Go Nose`, direct Npcap lab sensor, ETW, FIM, Registry, minifilter, WFP telemetry, or other approved sensor);
- canonical event ID and flow identity;
- detector ID/version and rule/provenance identity;
- detection verdict, severity, confidence, and correlation/incident ID;
- payload hash and bounded payload claim where available;
- forensic sequence/hash-chain position;
- configuration/policy version used for observation;
- timestamp and runtime generation.

The receipt means **“the IDS recorded this observation and verdict”**. It never means “the host was blocked,” “the WFP filter exists,” or “the threat was prevented.”

### 4. Sensor and intelligence rules

- Direct Npcap is an opt-in, disjoint, full-payload IDS sensor. It must never share an interface with Go Nose in production operation.
- ETW, FIM, Registry, minifilter, WFP telemetry, SIEM, Brain, RAG, federation, and XDR are evidence/advisory producers only.
- Threat intelligence and XDR may enrich or correlate evidence, but they cannot dispatch host effects.
- Brain/RAG recommendations require a recorded provenance chain and remain advisory.
- `real_ips_path`, `ips_canary`, and legacy WFP/blocking helpers remain outside the production daemon.

### 5. Promotion and rollback

New IDS sensors, detectors, or correlation rules must follow a detection-only promotion sequence:

1. static contract and authority review;
2. unit and component tests;
3. lab/canary observation with bounded scope and expiry;
4. evidence receipt and replay verification;
5. Windows host verification where applicable;
6. operator-approved production enablement;
7. rollback plan that disables the detector or route without deleting evidence.

No step grants host-effect authority.

## Consequences

### Positive

- IPS hardening work increases IDS trustworthiness without expanding the attack surface.
- Every detection can be traced from sensor to forensic record and replay.
- Direct Npcap can provide deep payload evidence while remaining isolated from canonical Go Nose acquisition.
- Detector promotion and rollback become controlled operations rather than ad hoc switches.
- Rust PEP remains the only privileged security truth.

### Negative

- The IDS pipeline gains receipt/provenance fields and additional verification work.
- Detection-only promotion is slower than directly enabling a new detector.
- Existing manifest claims for `proto_anomaly`, `threat_intel`, `rag`, and XDR must be reconciled with actual daemon wiring before implementation claims are updated.

## Rejected alternatives

1. **Let detectors call Rust PEP directly.** Rejected: creates detector-to-enforcement coupling and bypasses the single runtime decision path.
2. **Reuse IPS canary modules as the IDS production gate.** Rejected: their vocabulary and state model describe host effects, not evidence integrity.
3. **Treat an IDS receipt as an enforcement receipt.** Rejected: recording a detection is not proof of prevention.
4. **Make Brain/RAG the detection authority.** Rejected: they are advisory analytics and cannot own runtime orchestration.
5. **Run direct Npcap alongside Go Nose on the same interface.** Rejected: duplicate event identity and forensic ambiguity.

## Required follow-up slices

- IDS-INT-001: define and test the IDS Evidence Receipt at the forensic seam.
- IDS-NPCAP-002: connect direct Npcap full-payload observations to the existing IDS path with disjoint-interface proof.
- IDS-L7-003: add protocol anomaly evidence production without direct policy/enforcement calls.
- IDS-HOST-004: adapt host detector results into canonical evidence.
- IDS-XDR-005: select exactly one XDR correlation authority and connect it as evidence-only.
- MAP-006: reconcile runtime manifest, flow map, authority map, and evidence index with actual wiring.

## Completion invariant

A production IDS module is complete only when it can prove:

`approved sensor → canonical event → detector → correlation → forensic record → IDS Evidence Receipt → replay/evidence verification`

and can also prove that no path exists from that module directly to a host effect.
