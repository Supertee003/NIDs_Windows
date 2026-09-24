# L2 Named-Pipe Forensic Chain Audit

**Date:** 2026-09-24  
**Status:** Source-level chain complete; Windows runtime proof pending  
**Prevention gate:** `CLOSED`

## Verified source path

The production path is connected as follows:

```text
pipe_monitor.publishPipeObservation()
  -> EventPublisher callback
  -> nids_main.publishPipeObservation()
  -> event.IpcEvent(signature_match)
  -> event_queue.pushEvent(ev, payload)
  -> event_processor.pipelineLoop()
  -> processEvent()
  -> signature/anomaly/policy stages
  -> ForensicRing.append(ev, payload, audit_id, policy_id, pep_decision, severity)
```

The monitor is wired before the T5 thread starts. The adapter sets `capture_pipe_monitor`, preserves the observation timestamp, payload length, and bounded payload hash, and submits the original payload bytes to the queue. The queue copies the bounded payload before releasing the producer path.

`event_processor` preserves the queued event in a mutable local copy, runs the detector, updates `rule_id` and event kind when the Aho-Corasick engine matches, and appends the resulting event and payload to `ForensicRing`. This means a pipe match is not merely logged by the sensor; it enters the common detection and forensic path.

## Evidence boundaries

This is a source-level integration result, not a host-runtime proof. The remaining Windows acceptance evidence must show one captured native pipe enumeration, one canonical/queued event, one forensic record with source `capture_pipe_monitor`, the expected payload hash, and the corresponding rule identity. A benign non-matching pipe name must produce no detection record. The test must remain observe-only.

No PEP call, WFP mutation, block receipt, or prevention-gate transition occurs in this audit.
