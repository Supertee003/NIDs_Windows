# L7/WFP Mapping Boundary

**Date:** 2026-09-24  
**Status:** Implemented as observe-only metadata  
**Prevention gate:** `CLOSED`

## Finding

The WFP reader already receives bounded packet payload bytes, but its Event Fabric submission previously marked every event as `forward` without recording an application-layer classification. This made the L7 boundary invisible to downstream consumers even when the payload was available.

## Change

`src/capture/l7_classifier.zig` adds a bounded, signature-only classifier. It recognizes DNS, HTTP, TLS, SMB, RDP, and a narrow Kerberos marker. The classifier returns `unknown` for weak, malformed, or insufficient payloads. Destination ports are treated only as hints; they do not independently establish protocol identity.

`src/capture/windows_capture.zig` invokes the classifier before submitting the canonical event and writes the result into the existing `context_flags` extension area. The frozen CanonicalEvent v1 layout is unchanged. The following bits are assigned:

| Bit | Meaning |
|---:|---|
| 8 | DNS signature/classification |
| 9 | HTTP request method |
| 10 | TLS record header |
| 11 | SMB signature |
| 12 | RDP/TPKT header on TCP/3389 |
| 13 | Narrow Kerberos marker |

An event with no strong match keeps these bits clear. The event remains `forward`; L7 metadata is not a policy decision and cannot claim a host effect.

## Validation scope

The classifier contains unit tests for positive and negative cases. The Windows acceptance step must run `zig test src\\capture\\l7_classifier.zig -O Debug`, followed by the normal full test/build commands. A real host run must confirm that WFP payload frames reach the classifier and that the resulting context flags are visible in the forensic/event-fabric record.

This change does not call the PEP, install a WFP filter, alter rollback behavior, or open the prevention gate.
