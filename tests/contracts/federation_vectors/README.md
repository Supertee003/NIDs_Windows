# Federation Wire v1 Golden Vectors

12-byte header (magic u32 LE `AEGI`, version u8, msg_type u8,
payload_len u16 LE, crc32 u32 LE) + payload. All payload fields
little-endian; byte slices are `[u8 len][raw]`; f32 is bitcast LE;
CRC32 is IEEE (zlib). Frozen: a wire change regenerates every
vector in the same patch (one schema, N codecs).

## Vectors

### fed_v1_001.bin
- Description: Heartbeat node 7 -> broadcast, seq 1, no node/TI blocks
- Size: 51 bytes
- SHA256: `54f782748458e204469a619f9cb78425633b14b98a8d6e3d5e0f63071c851c2a`

### fed_v1_002.bin
- Description: Incident node 7 -> node 9 with announcement, DNS tunnel High 7.5
- Size: 112 bytes
- SHA256: `9a152efa803d6c73aa6f58d747c90147f0b2b67eaa9ffcd3e0c8588df23eedb6`

### fed_v1_003.bin
- Description: Threat-intel share node 9 -> broadcast, malicious IP 10.0.0.14
- Size: 94 bytes
- SHA256: `c1597e2177dd8bd4f9a27c6c186703c8938145b3ac9eb6b554d4dd2fc14712e7`

