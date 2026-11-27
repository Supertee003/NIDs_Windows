# Golden vectors — pointer (not a second vector set)

The shared vectors are under `tests/contracts/event_vectors/event_vectors/`
with their own [`README.md`](../../tests/contracts/event_vectors/event_vectors/README.md).
Zig, Go, C and the reference Python codec are pinned to the same schema;
Rust canonical codec is TBD and the Python brain codec is not production-wired.

This file is only a path alias. Do not add a second vector set here. A wire
change must update the shared `event_v*` vectors, every codec and the protocol
documents in one patch, then re-run the contract tests. Current framing answers
are in [`docs/protocol/INDEX.md`](INDEX.md); authoritative text is in
[`shared/protocol/wire_v3.md`](../../shared/protocol/wire_v3.md).
