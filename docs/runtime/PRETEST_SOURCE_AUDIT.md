# AEGIS NIDS — Pre-Test Source Audit

## Decision

ยังไม่เริ่มการทดสอบโจมตีจนกว่าจะ build binary ใหม่และตรวจ static/runtime contracts ครบ การทดสอบก่อนหน้านี้มีประโยชน์สำหรับค้นหา root cause แต่ไม่ใช่ acceptance run เพราะ canonical data path ยังมี legacy branch และ event metadata ยังไม่สมบูรณ์

## Findings closed in source

| Finding | Impact | Resolution |
|---|---|---|
| Sensor called legacy Event Fabric and `nids_analyze` | Transport succeeded but daemon-owned pipeline was bypassed | Sensor now submits to `event_queue.pushEvent` only |
| Overlapped pipe handle used with null `ReadFile` OVERLAPPED | Read behavior was not consistent with Win32 handle contract | Sensor read now uses overlapped operation and completion wait |
| Event ID was wall-clock milliseconds | Events sent in one millisecond could collide | Sensor owns a monotonic per-process event counter |
| Detector rule ID stayed local to processor | Audit and forensic records showed `rule=0` after a match | Processor persists matched rule ID and changes event kind to `signature_match` |
| Policy match counter was not incremented | Metrics understated policy decisions | Processor increments `g_pipeline_policies_matched` |
| Forensic severity used pre-policy event severity | Forensic record could omit escalated severity | Forensic append uses the evaluated event copy |
| Synthetic JSON metadata was discarded | Flow identity and protocol appeared as zero | Sensor maps IPv4, ports, protocol, and severity into `IpcEvent` |
| Generator had no real-rule benign fixtures | A successful transport did not prove detection | Generator now supports `xss`, `path-traversal`, and `command-injection` fixtures |

## Findings intentionally classified as separate gates

ETW, FIM, Registry, WFP, and minifilter failures are not silently treated as healthy. They remain explicit degraded capabilities. They must be repaired before a test that claims host telemetry or kernel enforcement coverage, but they do not block a sensor-only detection/forensic validation if the test declares that scope.

## Pre-test completion checklist

The implementation is not accepted until all of these are true:

1. Fresh Zig build succeeds from the current source; no stale `zig-out` binary is used.
2. Startup logs show the canonical sensor listener and no legacy Event Fabric call.
3. A `--fixture xss` event produces `Canonical event queued` and a non-zero detection.
4. Audit output carries a non-zero rule ID, source/destination identity, and protocol.
5. `events_processed`, `detections`, `policies_matched`, and `forensic_records` increase.
6. Forensic verification and replay succeed for the same event identity.
7. Health reports optional adapter failures as degraded capabilities, not as false success.
8. The scope is recorded as sensor-only, isolated lab, or approved adversarial scenario.

Only after this checklist passes should controlled attack testing begin.
