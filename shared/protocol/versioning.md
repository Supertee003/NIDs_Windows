# AEGIS Wire Protocol Versioning (Rewrite Phase 2)

## Version Numbers

### Wire Protocol Version
- Current: `1` (`AEGIS_WIRE_VERSION`)
- Magic: `0x57455631` ("WEV1")
- Bump when: wire frame layout changes (header fields, payload encoding)

### Event Schema Version
- Current: `1` (`AEGIS_EVENT_VERSION`)
- Magic: `0x41454731` ("AEG1")
- Bump when: canonical event fields change (add/remove/reorder)

### Version Compatibility Rules

1. **Forward compatible**: receivers can skip unknown trailing fields if `struct_size > expected`
2. **Backward compatible**: old clients can read v1 events (no breaking changes within v1)
3. **Version validation**: receivers MUST validate magic + version before reading fields
4. **Reserved field**: 16 bytes at end of payload — zero-filled, available for v2 fields

## Bump Procedure

When adding a new field to canonical event:
1. Add to `reserved[]` (use reserved bytes first)
2. If reserved is full → bump `EVENT_VERSION` to 2
3. Update `struct_size` to new total
4. All receivers must check `struct_size >= expected` before reading
5. If `struct_size < expected`, skip unknown fields

## Cross-Language Verification

Each language's wire codec must pass:
1. Encode known event → bytes match test vector exactly
2. Decode test vector → all fields match expected values
3. Round-trip (encode → decode) preserves all fields
4. CRC32 mismatch → reject
5. Wrong magic → reject
6. Wrong version → reject
7. Short buffer → reject
