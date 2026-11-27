# Canonical event — pointer (not a second specification)

Authoritative schema: [`shared/event/canonical_event.md`](../../shared/event/canonical_event.md) (FROZEN).  
Authoritative Zig codec: `src/contract/canonical_event.zig`.  
Answer sheet with source lines: [`docs/protocol/INDEX.md`](INDEX.md).

This file exists only so the requested path resolves. It records no field table of
its own; a field change must update the shared schema, all codecs and the shared
`event_v*` golden vectors in the **same** patch (AGENTS.md test-hygiene rule 3).
Production framing is v3; v1/v2 remain readable. Encoding a frame never
authorizes a host effect.
