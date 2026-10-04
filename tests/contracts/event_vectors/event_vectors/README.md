# Cross-Language Test Vectors for Canonical Event v1

## Format

Each .bin file is exactly 109 bytes (WIRE_PAYLOAD_SIZE).
All fields are little-endian, explicit field-by-field encoding.
No struct memcpy, no pointer cast.

## Vectors

### event_v1_001.bin
- Description: Benign forward event (192.168.1.100 -> 10.0.0.1:80)
- Size: 109 bytes
- SHA256: `05e3666ae7af714635ea2e781fc78ccd657655301e724ae977eb9452ecc323dd`
- Magic at offset 0: 0x31474541

### event_v1_002.bin
- Description: APT block event (192.168.16.16 -> 10.0.0.1:445 SMB)
- Size: 109 bytes
- SHA256: `837a3450aee44dbf13fea4c9d9cb07d56b042e0df5dc002daab9a17dd0bc9123`
- Magic at offset 0: 0x31474541

### event_v1_003.bin
- Description: Host event (process start, minifilter)
- Size: 109 bytes
- SHA256: `89910e32ec2c07d694cca7163052e49bdfaafdbdfc63a5d0305388c3bf03756a`
- Magic at offset 0: 0x31474541

### event_v1_004.bin
- Description: Edge case: all zeros except magic/version (custom event type)
- Size: 109 bytes
- SHA256: `cd9e8bf5056eae8889a49f725b5485b78fc4171bf29eaccb273ad68f4078a6b7`
- Magic at offset 0: 0x31474541

### event_v1_005.bin
- Description: Edge case: all max values (0xFF everywhere)
- Size: 109 bytes
- SHA256: `4c9bc9b96883737e81fd056f5f3b504c18289f909ba5bca4ce1278ac5a8ccd89`
- Magic at offset 0: 0x31474541

### event_v2_006.bin
- Description: IPv6 forward, full identity (2001:db8::1 -> 2001:db8::2:443)
- Size: 133 bytes (v2: 109 + 24 tail)
- SHA256: `33ba2e8c283b38d00769d828336f2ea841b9676fae24b9c7f99a3539f37d3517`
- Magic at offset 0: 0x31474541

