#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "aegis_wfp_payload.h"

static void test_inbound_data_starts_at_payload(void)
{
    const uint8_t data[] = { 'm', 'a', 'r', 'k' };
    size_t offset = 99;
    size_t length = 99;

    assert(aegis_wfp_get_payload_slice(data, sizeof(data), 6, 0,
        &offset, &length));
    assert(offset == 0);
    assert(length == sizeof(data));
    assert(memcmp(data + offset, "mark", 4) == 0);
}

static void test_outbound_tcp_skips_base_header(void)
{
    uint8_t data[20 + 4] = { 0 };
    size_t offset = 0;
    size_t length = 0;

    data[12] = 0x50; /* 20-byte TCP header */
    memcpy(data + 20, "mark", 4);
    assert(aegis_wfp_get_payload_slice(data, sizeof(data), 6, 1,
        &offset, &length));
    assert(offset == 20);
    assert(length == 4);
    assert(memcmp(data + offset, "mark", 4) == 0);
}

static void test_outbound_tcp_skips_options(void)
{
    uint8_t data[40 + 4] = { 0 };
    size_t offset = 0;
    size_t length = 0;

    data[12] = 0xA0; /* 40-byte TCP header including options */
    memcpy(data + 40, "mark", 4);
    assert(aegis_wfp_get_payload_slice(data, sizeof(data), 6, 1,
        &offset, &length));
    assert(offset == 40);
    assert(length == 4);
    assert(memcmp(data + offset, "mark", 4) == 0);
}

static void test_outbound_udp_skips_header_and_honors_length(void)
{
    uint8_t data[8 + 4 + 3] = { 0 };
    size_t offset = 0;
    size_t length = 0;

    data[4] = 0;
    data[5] = 12; /* UDP header + four data bytes; trailing bytes are excluded */
    memcpy(data + 8, "mark", 4);
    assert(aegis_wfp_get_payload_slice(data, sizeof(data), 17, 1,
        &offset, &length));
    assert(offset == 8);
    assert(length == 4);
    assert(memcmp(data + offset, "mark", 4) == 0);
}

static void test_malformed_or_unsupported_outbound_data_is_not_payload(void)
{
    uint8_t short_tcp[19] = { 0 };
    uint8_t bad_tcp_offset[20] = { 0 };
    uint8_t tcp_offset_past_end[20] = { 0 };
    uint8_t bad_udp_length[8] = { 0 };
    uint8_t udp_length_past_end[8] = { 0 };
    uint8_t unsupported[8] = { 0 };
    size_t offset = 99;
    size_t length = 99;

    assert(!aegis_wfp_get_payload_slice(short_tcp, sizeof(short_tcp), 6, 1,
        &offset, &length));
    assert(offset == 0 && length == 0);

    bad_tcp_offset[12] = 0x40; /* Data offset below TCP minimum */
    assert(!aegis_wfp_get_payload_slice(bad_tcp_offset, sizeof(bad_tcp_offset), 6, 1,
        &offset, &length));
    assert(offset == 0 && length == 0);

    tcp_offset_past_end[12] = 0x60; /* 24-byte header, only 20 bytes available */
    assert(!aegis_wfp_get_payload_slice(tcp_offset_past_end,
        sizeof(tcp_offset_past_end), 6, 1, &offset, &length));
    assert(offset == 0 && length == 0);

    bad_udp_length[4] = 0;
    bad_udp_length[5] = 7; /* Shorter than the UDP header */
    assert(!aegis_wfp_get_payload_slice(bad_udp_length, sizeof(bad_udp_length), 17, 1,
        &offset, &length));
    assert(offset == 0 && length == 0);

    udp_length_past_end[4] = 0;
    udp_length_past_end[5] = 12; /* Declares bytes unavailable in this NBL */
    assert(!aegis_wfp_get_payload_slice(udp_length_past_end,
        sizeof(udp_length_past_end), 17, 1, &offset, &length));
    assert(offset == 0 && length == 0);

    assert(!aegis_wfp_get_payload_slice(unsupported, sizeof(unsupported), 1, 1,
        &offset, &length));
    assert(offset == 0 && length == 0);
}

int main(void)
{
    test_inbound_data_starts_at_payload();
    test_outbound_tcp_skips_base_header();
    test_outbound_tcp_skips_options();
    test_outbound_udp_skips_header_and_honors_length();
    test_malformed_or_unsupported_outbound_data_is_not_payload();
    puts("WFP payload slice tests: PASS (5 cases)");
    return 0;
}
