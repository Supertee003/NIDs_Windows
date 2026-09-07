# ADR-0003: Canonical Event Authority and Captured-Source Ownership

**Status:** Accepted  
**Date:** 2026-09-07  
**Supersedes:** the implicit "C++ owns the event schema" reading of the legacy G1 gate doc (`bridge/aegis_ipc.hpp` `IpcEvent` as source of truth), which contradicts ADR-0001/0002

## Context

ADR-0001/0002 declared `core/canonical_event.zig` the event-schema authority and
`core/` the canonical runtime, but `docs/architecture/authority-matrix.md` still
named `bridge/aegis_ipc.hpp` (`IpcEvent`, 72-byte wire, schema_version 2) as the
C++ "source of truth" — a doc-level conflict with the locked contract, and a
live duplication of the event model across C++ and Zig. Separately, packet
capture existed twice: `core/npcap_capture.zig` (Zig calling wpcap.dll) and the
Go Nose TUI (`nose/`), while the C++ framework owned no capture path at all.

The T2 requirement is a single canonical event for the whole runtime, tested for
serialize/deserialize/version/malformed/compatibility, with real (not stub)
acquisition reaching the runtime as CanonicalEvent.

## Decision

1. **Single event authority = Zig `core/canonical_event.zig`.** Wire format is
   the 109-byte `CanonicalEvent` (magic `0x41454731` "AEG1", version 1),
   explicitly field-by-field encoded, verified by a cross-language golden vector
   embedded in both the Zig tests and the Go tests. `bridge/aegis_ipc.hpp`
   (`IpcEvent` 72-byte) and `src/contract/event.zig` (`IpcEvent` 80-byte,
   magic 0xAE615011) are LEGACY and must not be extended.
2. **Packet capture is owned by Go Nose** (`nose/capture.go`, gopacket/npcap),
   acquisition-only per ADR-0001 — no detection, no policy in Go. Captured
   packets are encoded as CanonicalEvent and streamed to the Zig core over the
   named pipe `\\.\pipe\aegis_nose` (frame = u32 LE length + 109 raw wire
   bytes). `core/npcap_capture.zig` is LEGACY.
3. **Host-source acquisition is owned by the C++ adapter framework**
   (`bridge/aegis_adapter.hpp/.cpp`) covering ETW, FIM, Registry, Process (and
   Windows networking), exposed to Zig over a C ABI with
   start/stop/poll/callback/health/error. Zig must not call Win32 APIs directly
   for these sources once the boundary exists.

## Considered Options

- **A. C++ = source of truth** (follow the legacy authority-matrix line).
  Rejected: contradicts ADR-0001/0002; would leave two event models live.
- **B. Zig = authority, C++ keeps capture.** Rejected: C++ framework has no
  packet-capture path and the Go Nose already has a working npcap capture;
  keeping capture in C++ would duplicate Go's path.
- **C (chosen). Zig = event authority; Go = network capture; C++ = host
  adapters.** Each language owns exactly one acquisition concern, one event
  model, and the C++ boundary is ABI-visible for testability.

## Consequences

1. `docs/architecture/authority-matrix.md` rewired: Canonical Event authority =
   `core/canonical_event.zig` (Zig); legacy authorities listed explicitly.
2. ALL languages must emit/consume the 109-byte canonical wire. Go has a golden
   vector; C++ adapter frames use the same canonical layout.
3. `runtime_manifest.json` v3 updated with the new modules
   (`nose/canonical.go`, `nose/capture.go`, `nose/pipe_writer.go`,
   `bridge/aegis_adapter.*`, `core/nose_pipe_reader.zig`, `core/cpp_adapter.zig`).
4. T3 must land the build switch so `core/` becomes the built runtime and the
   pipe reader / adapter binding are wired into production startup.

## References

- ADR-0001 (architecture lock), ADR-0002 (core/ is canonical runtime)
- docs/architecture/authority-matrix.md (rewired)
- docs/contracts/canonical-event-v1.md
- runtime_manifest.json (v3)