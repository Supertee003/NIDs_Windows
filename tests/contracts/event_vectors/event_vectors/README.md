# Cross-Language Test Vectors for Canonical Event v1

## Format

Each .bin file is exactly 109 bytes (WIRE_PAYLOAD_SIZE).
All fields are little-endian, explicit field-by-field encoding.
No struct memcpy, no pointer cast.

## Vectors

### event_v1_001.bin
- Description: Benign forward event (192.168.1.100 -> 10.0.0.1:80)
- Size: 109 bytes
- SHA256: `7e22844acb491e13bcd10b2fe59092f82562a27ea784962c08cd1cad569d88bf`
- Magic at offset 0: 0x31474541

### event_v1_002.bin
- Description: APT block event (192.168.16.16 -> 10.0.0.1:445 SMB)
- Size: 109 bytes
- SHA256: `0e82a6225b1d42ef6bda7fe0a8ab24df2ddcc358c76ce8c963b36dac67d6d5d1`
- Magic at offset 0: 0x31474541

### event_v1_003.bin
- Description: Host event (process start, minifilter)
- Size: 109 bytes
- SHA256: `06018ab713e82dd6542d5ff43a41bb29f1d78d974db5aafc58a45ed82b127a07`
- Magic at offset 0: 0x31474541

### event_v1_004.bin
- Description: Edge case: all zeros except magic/version (custom event type)
- Size: 109 bytes
- SHA256: `06f1edfe57bf722ad208d9fa26b695a7a2fe0facfffa7c8e8093d1a26fe969c7`
- Magic at offset 0: 0x31474541

### event_v1_005.bin
- Description: Edge case: all max values (0xFF everywhere)
- Size: 109 bytes
- SHA256: `5cd1d8fdcbf10ef9d4706164572ee422e02a4ad15c0d3e42b1e387a7295fe177`
- Magic at offset 0: 0x31474541

