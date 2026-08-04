/**
 * aegis_bridge_test.cpp — AEGIS IPC Bridge Unit Tests
 *
 * Tests all extern "C" API functions:
 *   - init/shutdown
 *   - push/pop events
 *   - DEFCON calculation
 *   - Packet parsing
 *   - NOP sled detection
 *   - Malformed header detection
 *   - Queue overflow
 */

#include "aegis_ipc.hpp"
#include "aegis_packet_parser.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>

static int g_testsPassed = 0;
static int g_testsFailed = 0;

#define TEST_ASSERT(cond, msg) do { \
    if (cond) { \
        g_testsPassed++; \
        fprintf(stdout, "  [PASS] %s\n", msg); \
    } else { \
        g_testsFailed++; \
        fprintf(stderr, "  [FAIL] %s (line %d)\n", msg, __LINE__); \
    } \
} while(0)

int main() {
    fprintf(stdout, "\n========================================\n");
    fprintf(stdout, "  AEGIS Bridge — Unit Tests\n");
    fprintf(stdout, "========================================\n\n");

    // ====== Test 1: Init/Shutdown ======
    fprintf(stdout, "--- Test 1: Init/Shutdown ---\n");
    TEST_ASSERT(aegis_bridge_init() == 0, "Bridge init succeeds");
    TEST_ASSERT(aegis_bridge_init() == 0, "Double init returns success");
    TEST_ASSERT(aegis_bridge_shutdown() == 0, "Bridge shutdown succeeds");
    TEST_ASSERT(aegis_bridge_shutdown() == 0, "Double shutdown returns success");

    // ====== Test 2: Push/Pop Events ======
    fprintf(stdout, "\n--- Test 2: Push/Pop Events ---\n");
    aegis_bridge_init();

    Aegis::Bridge::IpcEvent event = {};
    event.event_type = Aegis::Bridge::kNetworkEvent;
    event.source_ip = 0xC0A80101;  // 192.168.1.1
    event.dest_ip = 0x0A000101;    // 10.0.1.1
    event.source_port = 12345;
    event.dest_port = 80;
    event.protocol = 6;  // TCP
    event.tier_result = 1;
    event.rule_id = 56;
    event.severity = Aegis::Bridge::kSeverityCritical;

    TEST_ASSERT(aegis_bridge_push_event(&event) == 0, "Push event succeeds");
    TEST_ASSERT(aegis_bridge_get_event_count() == 1, "Event count is 1");

    Aegis::Bridge::IpcEvent outEvent;
    TEST_ASSERT(aegis_bridge_pop_event(&outEvent) == 0, "Pop event succeeds");
    TEST_ASSERT(outEvent.source_ip == 0xC0A80101, "Popped source_ip matches");
    TEST_ASSERT(outEvent.dest_port == 80, "Popped dest_port matches");
    TEST_ASSERT(outEvent.severity == Aegis::Bridge::kSeverityCritical, "Popped severity matches");
    TEST_ASSERT(aegis_bridge_get_event_count() == 0, "Queue empty after pop");

    // ====== Test 3: Multiple Events ======
    fprintf(stdout, "\n--- Test 3: Multiple Events ---\n");
    for (int i = 0; i < 50; i++) {
        event.source_ip = 0xC0A80101 + i;
        event.severity = (i % 4 == 0) ? 3 : 1;
        aegis_bridge_push_event(&event);
    }
    TEST_ASSERT(aegis_bridge_get_event_count() == 50, "50 events pushed");

    int popped = 0;
    while (aegis_bridge_pop_event(&outEvent) == 0) popped++;
    TEST_ASSERT(popped == 50, "50 events popped");
    TEST_ASSERT(aegis_bridge_get_event_count() == 0, "Queue empty after popping all");

    // ====== Test 4: DEFCON Calculation ======
    fprintf(stdout, "\n--- Test 4: DEFCON Calculation ---\n");

    // DEFCON 5 (SAFE): 0 alerts
    aegis_bridge_update_defcon(0, 0, 0, 0);
    TEST_ASSERT(aegis_bridge_get_defcon() == 5, "DEFCON 5 (SAFE) when 0 alerts");

    // DEFCON 4 (ELEVATED): 1-5 alerts
    aegis_bridge_update_defcon(0, 0, 0, 3);
    TEST_ASSERT(aegis_bridge_get_defcon() == 4, "DEFCON 4 (ELEVATED) when 3 alerts");

    // DEFCON 3 (HIGH): 5+ alerts OR 1+ critical
    aegis_bridge_update_defcon(1, 0, 0, 3);
    TEST_ASSERT(aegis_bridge_get_defcon() == 3, "DEFCON 3 (HIGH) when 1 critical");

    aegis_bridge_update_defcon(0, 0, 0, 7);
    TEST_ASSERT(aegis_bridge_get_defcon() == 3, "DEFCON 3 (HIGH) when 7 alerts");

    // DEFCON 2 (SEVERE): 5+ critical OR 3+ blocks
    aegis_bridge_update_defcon(5, 0, 0, 10);
    TEST_ASSERT(aegis_bridge_get_defcon() == 2, "DEFCON 2 (SEVERE) when 5 critical");

    aegis_bridge_update_defcon(0, 3, 0, 10);
    TEST_ASSERT(aegis_bridge_get_defcon() == 2, "DEFCON 2 (SEVERE) when 3 blocks");

    // DEFCON 1 (MAXIMUM): 10+ critical OR 5+ blocks OR kernel threats
    aegis_bridge_update_defcon(10, 0, 0, 20);
    TEST_ASSERT(aegis_bridge_get_defcon() == 1, "DEFCON 1 (MAXIMUM) when 10 critical");

    aegis_bridge_update_defcon(0, 5, 0, 10);
    TEST_ASSERT(aegis_bridge_get_defcon() == 1, "DEFCON 1 (MAXIMUM) when 5 blocks");

    aegis_bridge_update_defcon(0, 0, 1, 3);
    TEST_ASSERT(aegis_bridge_get_defcon() == 1, "DEFCON 1 (MAXIMUM) when kernel threat");

    // ====== Test 5: DEFCON Labels ======
    fprintf(stdout, "\n--- Test 5: DEFCON Labels ---\n");
    aegis_bridge_update_defcon(0, 0, 0, 0);
    TEST_ASSERT(strcmp(aegis_bridge_get_defcon_label(), "SAFE") == 0, "Label SAFE");
    TEST_ASSERT(strlen(aegis_bridge_get_defcon_description()) > 10, "Description exists");

    aegis_bridge_update_defcon(10, 0, 0, 20);
    TEST_ASSERT(strcmp(aegis_bridge_get_defcon_label(), "MAXIMUM") == 0, "Label MAXIMUM");

    // ====== Test 6: Packet Parser — Valid IPv4+TCP ======
    fprintf(stdout, "\n--- Test 6: Packet Parser (IPv4+TCP) ---\n");
    uint8_t rawPacket[40] = {};
    rawPacket[0] = 0x45;  // Version=4, IHL=5 (20 bytes)
    rawPacket[2] = 0x00; rawPacket[3] = 0x28;  // Total length=40
    rawPacket[8] = 0x40;  // TTL=64
    rawPacket[9] = 0x06;  // Protocol=TCP
    rawPacket[12] = 0xC0; rawPacket[13] = 0xA8; rawPacket[14] = 0x01; rawPacket[15] = 0x01;  // 192.168.1.1
    rawPacket[16] = 0x0A; rawPacket[17] = 0x00; rawPacket[18] = 0x01; rawPacket[19] = 0x01;  // 10.0.1.1
    rawPacket[20] = 0x30; rawPacket[21] = 0x39;  // src port 12345
    rawPacket[22] = 0x00; rawPacket[23] = 0x50;  // dst port 80
    rawPacket[32] = 0x50;  // Data offset=5 (20 bytes)

    Aegis::Bridge::IpcEvent parsedEvent;
    int32_t parseResult = aegis_parse_packet(rawPacket, 40, &parsedEvent);
    TEST_ASSERT(parseResult == 0, "Parse valid IPv4+TCP packet");
    TEST_ASSERT(parsedEvent.protocol == 6, "Protocol is TCP (6)");

    // ====== Test 7: NOP Sled Detection ======
    fprintf(stdout, "\n--- Test 7: NOP Sled Detection ---\n");
    uint8_t nopSled[20];
    memset(nopSled, 0x90, 20);
    TEST_ASSERT(aegis_check_nop_sled(nopSled, 20, 5) == 1, "NOP sled detected (20 bytes of 0x90)");

    uint8_t normalData[20] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20};
    TEST_ASSERT(aegis_check_nop_sled(normalData, 20, 5) == 0, "Normal data — no NOP sled");

    uint8_t shortNop[3] = {0x90, 0x90, 0x90};
    TEST_ASSERT(aegis_check_nop_sled(shortNop, 3, 5) == 0, "Short NOP (<5) — not detected");

    // ====== Test 8: Malformed Header Detection ======
    fprintf(stdout, "\n--- Test 8: Malformed Header Detection ---\n");
    uint8_t malformedPacket[40] = {};
    malformedPacket[0] = 0x55;  // Version=5 (INVALID — should be 4)
    malformedPacket[9] = 0x06;  // TCP
    TEST_ASSERT(aegis_check_malformed(malformedPacket, 40) == 1, "Malformed IPv4 version detected");

    // ====== Test 9: IPS Block/Unblock ======
    fprintf(stdout, "\n--- Test 9: IPS Block/Unblock ---\n");
    TEST_ASSERT(aegis_bridge_block_ip(0xC0A80101) == 0, "Block IP 192.168.1.1");
    TEST_ASSERT(aegis_bridge_unblock_ip(0xC0A80101) == 0, "Unblock IP 192.168.1.1");

    // ====== Test 10: Dropped Events ======
    fprintf(stdout, "\n--- Test 10: Dropped Events (overflow) ---\n");
    aegis_bridge_shutdown();
    aegis_bridge_init();

    // Push 9000 events (queue capacity is 8192)
    for (int i = 0; i < 9000; i++) {
        event.source_ip = i;
        aegis_bridge_push_event(&event);
    }
    TEST_ASSERT(aegis_bridge_get_event_count() == 8192, "Queue full at 8192");
    TEST_ASSERT(aegis_bridge_get_dropped_count() > 0, "Events dropped on overflow");

    // ====== Summary ======
    aegis_bridge_shutdown();

    fprintf(stdout, "\n========================================\n");
    fprintf(stdout, "  Results: %d passed, %d failed\n", g_testsPassed, g_testsFailed);
    fprintf(stdout, "========================================\n");

    return g_testsFailed > 0 ? 1 : 0;
}
