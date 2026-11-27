# Wire format — pointer (not a second specification)

Authoritative framing: [`shared/protocol/wire_v1.md`](../../shared/protocol/wire_v1.md),
[`wire_v2.md`](../../shared/protocol/wire_v2.md),
[`wire_v3.md`](../../shared/protocol/wire_v3.md) (v3 ACTIVE).  
Question-by-question answer sheet with source lines: [`docs/protocol/INDEX.md`](INDEX.md).

This file is a path alias for reviewers. The active Nose pipe frame is a 4-byte
little-endian length prefix followed by a raw frame whose version is at bytes
4–5; exact per-version length is required and invalid frames are rejected with a
counter, never silently truncated. See `INDEX.md` for endianness, size limits,
required/optional fields and unknown-version handling.
