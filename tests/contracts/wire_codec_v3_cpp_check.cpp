// ============================================================
// tests/contracts/wire_codec_v3_cpp_check.cpp
// ============================================================
// PAYLOAD-ENVELOPE-V3-001 (C++ leg).
//
// The C++ reference header is the byte-identity authority every other
// codec is written against, but nothing in the build compiled it: v3 was
// added to `shared/wire/wire_codec.h` with no translation unit exercising
// it. This harness closes that gap without a new build system: compile it
// with the same golden vectors the Zig/Go/Python codecs pin, and it must
// pass byte-identically.
//
// Checks, mirroring tests/contracts/test_payload_envelope_v3.py:
//   V1. Committed v3 vectors decode to their identity + payload + envelope.
//   V2. Re-encoding a decoded v3 frame reproduces the committed bytes.
//   V3. Strict envelope guards fail closed (crc, length, completeness,
//       presence, reserved byte, dirty v6 tail, trailing bytes).
//   V4. v1/v2 vectors stay metadata-only and round-trip byte-identically.
//
// Build + run (no artifacts land in the tree; see tests/contracts/README
// or the evidence artifact for the exact command):
//   g++ -std=c++17 -Wall -Wextra -I. tests/contracts/wire_codec_v3_cpp_check.cpp
//   then run the produced binary with the vector directory as argv[1].
// ============================================================

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "shared/wire/wire_codec.h"

namespace {

int g_failures = 0;

void check(bool ok, const char* what) {
    if (!ok) {
        std::fprintf(stderr, "FAIL: %s\n", what);
        ++g_failures;
    }
}

std::vector<uint8_t> read_file(const std::string& path) {
    std::vector<uint8_t> bytes;
    std::FILE* f = std::fopen(path.c_str(), "rb");
    if (f == nullptr) return bytes;
    uint8_t chunk[4096];
    size_t n = 0;
    while ((n = std::fread(chunk, 1, sizeof chunk, f)) > 0) {
        bytes.insert(bytes.end(), chunk, chunk + n);
    }
    std::fclose(f);
    return bytes;
}

std::string join(const std::string& dir, const char* name) {
    return dir + "/" + name;
}

// Decode one v3 vector, then re-encode it and require the exact bytes back.
void check_v3_vector(const std::string& dir, const char* name, bool expect_v6,
                     uint16_t expect_completeness, size_t expect_payload_len) {
    const std::vector<uint8_t> wire = read_file(join(dir, name));
    if (wire.empty()) {
        std::fprintf(stderr, "FAIL: cannot read %s\n", name);
        ++g_failures;
        return;
    }

    aegis::CanonicalEvent ev;
    aegis::V3Envelope env;
    const uint8_t* payload = nullptr;
    size_t payload_len = 0;
    const bool decoded = aegis::aegis_wire_decode_event_v3(
        wire.data(), wire.size(), ev, env, &payload, &payload_len);
    if (!decoded) {
        std::fprintf(stderr, "FAIL: %s did not decode\n", name);
        ++g_failures;
        return;
    }

    check(ev.version == aegis::EVENT_VERSION_V3, "decoded version is 3");
    check(env.completeness == expect_completeness, "completeness ordinal");
    check(payload_len == expect_payload_len, "payload length matches fresh");
    check(wire.size() == aegis::WIRE_V3_HEADER_SIZE + payload_len,
          "frame length is header + payload_len");
    check(((ev.context_flags & aegis::CONTEXT_V6_TRUNCATED) != 0) == expect_v6,
          "v6 tail presence matches the vector");

    std::vector<uint8_t> rebuilt(aegis::WIRE_V3_MAX_SIZE, 0);
    const size_t n = aegis::aegis_wire_encode_event_v3(
        rebuilt.data(), rebuilt.size(), ev, env, payload, payload_len);
    check(n == wire.size(), "re-encoded length matches the committed frame");
    if (n == wire.size()) {
        check(std::memcmp(rebuilt.data(), wire.data(), n) == 0,
              "re-encoded bytes are identical to the committed frame");
    }

    // Envelope round-trip: the decoder's product must re-validate, and the
    // dispatch path must accept the same frame without a payload argument.
    check(aegis::aegis_v3_envelope_valid(env, payload, payload_len),
          "decoded envelope re-validates");
    aegis::CanonicalEvent via_dispatch;
    check(aegis::aegis_wire_decode_event_dispatch(
              wire.data(), wire.size(), via_dispatch),
          "version dispatch accepts the v3 frame");
    check(via_dispatch.event_id == ev.event_id,
          "dispatch agrees on event identity");
}

// v1/v2 must stay metadata-only and byte-identical.
void check_frozen_vector(const std::string& dir, const char* name) {
    const std::vector<uint8_t> wire = read_file(join(dir, name));
    if (wire.empty()) {
        std::fprintf(stderr, "FAIL: cannot read %s\n", name);
        ++g_failures;
        return;
    }

    aegis::CanonicalEvent ev;
    if (!aegis::aegis_wire_decode_event_dispatch(wire.data(), wire.size(), ev)) {
        std::fprintf(stderr, "FAIL: %s did not decode\n", name);
        ++g_failures;
        return;
    }

    std::vector<uint8_t> rebuilt(aegis::WIRE_V3_MAX_SIZE, 0);
    size_t n = 0;
    if (wire.size() == aegis::WIRE_PAYLOAD_SIZE) {
        n = aegis::aegis_wire_encode_event(rebuilt.data(), rebuilt.size(), ev);
    } else if (wire.size() == aegis::WIRE_V2_PAYLOAD_SIZE) {
        n = aegis::aegis_wire_encode_event_v2(rebuilt.data(), rebuilt.size(), ev);
    } else {
        std::fprintf(stderr, "FAIL: %s has an unexpected frozen size\n", name);
        ++g_failures;
        return;
    }
    check(n == wire.size(), "frozen frame re-encodes at the same length");
    if (n == wire.size()) {
        check(std::memcmp(rebuilt.data(), wire.data(), n) == 0,
              "frozen frame bytes are unchanged");
    }
}

// Strict guards: every mutation below must be rejected, never inferred.
void check_strict_rejections(const std::string& dir) {
    const std::vector<uint8_t> good = read_file(join(dir, "event_v3_007.bin"));
    if (good.empty()) {
        ++g_failures;
        return;
    }

    struct Case {
        const char* what;
        size_t offset;
        bool clear_provenance_flag;
    };
    // Offsets are frame-relative: 133 = envelope start, 135 = completeness,
    // 136 = reserved, 137 = payload_len, 141 = payload_crc32, 153 = epoch.
    const Case cases[] = {
        {"crc mismatch rejected", 141, false},
        {"payload_len mismatch rejected", 137, false},
        {"unknown completeness rejected", 135, false},
        {"non-zero reserved byte rejected", 136, false},
        {"provenance field without flag rejected", 153, true},
    };

    for (const Case& c : cases) {
        std::vector<uint8_t> bad = good;
        if (c.clear_provenance_flag) {
            // Provenance is only meaningful when flags bit1 is set; clear it
            // and then the non-zero provenance field must be refused.
            const uint16_t flags = aegis::read_u16_le(bad.data() + 133);
            aegis::write_u16_le(bad.data() + 133,
                                (uint16_t)(flags & ~aegis::V3_FLAG_PROVENANCE_VALID));
            bad[c.offset] = static_cast<uint8_t>(bad[c.offset] | 0x01);
        } else {
            // Flip the byte so the mutation cannot coincide with the
            // original value and silently pass the guard.
            bad[c.offset] = static_cast<uint8_t>(bad[c.offset] ^ 0xFF);
        }
        aegis::CanonicalEvent ev;
        aegis::V3Envelope env;
        const uint8_t* payload = nullptr;
        size_t payload_len = 0;
        const bool accepted = aegis::aegis_wire_decode_event_v3(
            bad.data(), bad.size(), ev, env, &payload, &payload_len);
        check(!accepted, c.what);
    }

    // Truncated transport frame (one byte short) must be rejected as well.
    std::vector<uint8_t> short_frame(good.begin(), good.end() - 1);
    aegis::CanonicalEvent ev;
    aegis::V3Envelope env;
    const uint8_t* payload = nullptr;
    size_t payload_len = 0;
    check(!aegis::aegis_wire_decode_event_v3(short_frame.data(),
                                             short_frame.size(), ev, env,
                                             &payload, &payload_len),
          "frame one byte short of payload_len rejected");

    // Trailing bytes are not a v3 frame.
    std::vector<uint8_t> long_frame = good;
    long_frame.push_back(0x00);
    check(!aegis::aegis_wire_decode_event_v3(long_frame.data(),
                                             long_frame.size(), ev, env,
                                             &payload, &payload_len),
          "trailing bytes rejected");

    // Dirty v6 tail when bit2 is clear (vector 009 is a v4 metadata frame).
    const std::vector<uint8_t> v4 = read_file(join(dir, "event_v3_009.bin"));
    if (!v4.empty() && v4.size() > 140) {
        std::vector<uint8_t> dirty = v4;
        dirty[120] = 0x7F; // inside the 24-byte tail
        check(!aegis::aegis_wire_decode_event_v3(dirty.data(), dirty.size(),
                                                 ev, env, &payload, &payload_len),
              "dirty v6 tail with bit2 clear rejected");
    }

    // Oversized payload: a frame claiming more than the cap must not decode.
    aegis::V3Envelope big{};
    big.flags = aegis::V3_FLAG_PAYLOAD_PRESENT;
    big.completeness = aegis::PAYLOAD_COMPLETE;
    big.payload_len = aegis::V3_MAX_PAYLOAD + 1;
    big.original_len = big.payload_len;
    std::vector<uint8_t> oversize(aegis::V3_MAX_PAYLOAD + 1, 0xAA);
    big.payload_crc32 = aegis::aegis_crc32(oversize.data(), oversize.size());
    check(!aegis::aegis_v3_envelope_valid(big, oversize.data(), oversize.size()),
          "oversized payload rejected by the envelope guard");
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <vector-dir>\n", argv[0]);
        return 2;
    }
    const std::string dir = argv[1];

    check_v3_vector(dir, "event_v3_007.bin", true,
                    aegis::PAYLOAD_COMPLETE, 32);
    check_v3_vector(dir, "event_v3_008.bin", false,
                    aegis::PAYLOAD_TRUNCATED, 64);
    check_v3_vector(dir, "event_v3_009.bin", false,
                    aegis::PAYLOAD_METADATA_ONLY, 0);

    for (const char* name : {"event_v1_001.bin", "event_v1_002.bin",
                             "event_v1_003.bin", "event_v1_004.bin",
                             "event_v1_005.bin", "event_v2_006.bin"}) {
        check_frozen_vector(dir, name);
    }

    check_strict_rejections(dir);

    if (g_failures != 0) {
        std::fprintf(stderr, "wire_codec_v3_cpp_check: %d failure(s)\n",
                     g_failures);
        return 1;
    }
    std::printf("wire_codec_v3_cpp_check: PASS\n");
    return 0;
}
