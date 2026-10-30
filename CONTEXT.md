# AEGIS NIDS Windows

A Security Operations Machine: a Windows-native network intrusion detection
system that senses packets, decides threats, authorizes responses, and
records evidence. One hub runtime with specialist planes around it.

## Language

### Sensing

**Canonical Event**:
The single agreed-upon record of one observed network happening.
_Avoid_: raw packet, alert, log line

**Flow**:
The two-directional conversation a Canonical Event belongs to, keyed by
its endpoints.
_Avoid_: session, connection, stream

### Deciding

**Detection**:
A machine judgment that an event matches something known bad.
_Avoid_: alert, hit, finding

**Anomaly**:
A machine judgment that an event deviates from learned normal.
_Avoid_: outlier, abnormality

**Correlation**:
The combining of multiple Detections into one bigger picture.
_Avoid_: grouping, aggregation

**Incident**:
A tracked security case opened when correlated threat crosses a
threshold. Incidents escalate; Detections do not.
_Avoid_: alert, case, ticket

**Detection Authority**:
The Zig Runtime Spine's authority to orchestrate detectors, correlation, and
the detection verdict. A sensor acquires evidence; it does not own this
authority. The Detection Authority cannot approve a privileged host effect.
_Avoid_: enforcement authority, sensor authority

**IDS Evidence Receipt**:
The immutable acknowledgement that the IDS accepted and recorded one
detector result with its source, event identity, provenance, and forensic
position. It proves recording and traceability only; it never proves that a
host effect occurred.
_Avoid_: enforcement receipt, block receipt

### Authorizing

**Policy**:
A written rule stating which response a situation earns.
_Avoid_: rule, signature

**PEP**:
Policy Enforcement Point. The sole authority that may approve a
privileged action. Nothing else enforces, however certain it is.
_Avoid_: enforcer, firewall, blocker

**Receipt**:
The signed proof that the PEP approved one specific action. No receipt,
no host effect was performed — regardless of what was requested.
_Avoid_: ticket, token, approval

**Quarantine**:
The isolation response. Requested through the PEP like any privileged
action; never self-declared.
_Avoid_: isolation, sandbox, block

### Recording

**Forensic Record**:
The tamper-evident account of what happened, decided, and done,
chained to the record before it.
_Avoid_: log entry, audit row

**Decision Trace**:
The compact account of one decision: what was seen, which Policy
matched, what the PEP answered.
_Avoid_: trace log, debug trace

**DEFCON**:
The five-step readiness posture derived from live detections and
confirmed blocks. Computed by the runtime, never asserted by a file.
_Avoid_: threat level, alert level

### Operating

**Nose**:
The packet acquisition sensor. It smells traffic and produces Canonical
Events; it never decides policy and never enforces.
_Avoid_: sniffer, tap, collector

**Brain**:
The analytics advisor. It recommends, explains, and enriches; it never
authorizes, never enforces, never touches enforcement mechanisms.
_Avoid_: AI, model, engine

**Trust Store**:
The custodian of keys and certificates that verification depends on.
_Avoid_: keychain, vault, keystore
