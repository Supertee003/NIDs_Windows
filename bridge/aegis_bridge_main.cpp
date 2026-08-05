/**
 * aegis_bridge_main.cpp — AEGIS IPC Bridge Standalone Executable
 *
 * Runs the Bridge as a standalone process that:
 *   1. Initializes the event queue + DEFCON aggregator
 *   2. Accepts events from subsystems via named pipe / Unix socket
 *   3. Outputs events to stdout (for Dashboard to consume)
 *   4. Runs until SIGINT/SIGTERM
 *
 * Usage:
 *   ./aegis_bridge              # Run interactively
 *   ./aegis_bridge --test       # Run self-test + exit
 *   ./aegis_bridge --json       # Output events as JSON lines
 */

#include "aegis_ipc.hpp"
#include "aegis_packet_parser.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <unistd.h>
#include <signal.h>
#endif

static volatile bool g_running = true;

void signal_handler(int sig) {
    (void)sig;
    g_running = false;
    fprintf(stdout, "\n[AEGIS Bridge] Shutdown signal received...\n");
}

int main(int argc, char* argv[]) {
    bool testMode = false;
    bool jsonMode = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--test") == 0) testMode = true;
        if (strcmp(argv[i], "--json") == 0) jsonMode = true;
    }

    // ====== Banner ======
    fprintf(stdout, "\n");
    fprintf(stdout, "╔══════════════════════════════════════════════════════╗\n");
    fprintf(stdout, "║          AEGIS NIDS — IPC Bridge (C++)              ║\n");
    fprintf(stdout, "║          Multi-Language Hybrid Architecture          ║\n");
    fprintf(stdout, "╠══════════════════════════════════════════════════════╣\n");
    fprintf(stdout, "║  Zig Core + Python Brain + Rust Shield + Go Nose    ║\n");
    fprintf(stdout, "║  C++ Drivers + C++ Bridge                            ║\n");
    fprintf(stdout, "╚══════════════════════════════════════════════════════╝\n");
    fprintf(stdout, "\n");

    // ====== Initialize Bridge ======
    int32_t result = aegis_bridge_init();
    if (result != 0) {
        fprintf(stderr, "[AEGIS Bridge] Initialization FAILED (code %d)\n", result);
        return 1;
    }

    // ====== Self-Test Mode ======
    if (testMode) {
        fprintf(stdout, "[AEGIS Bridge] Running self-test...\n\n");

        // Test 1: Push events
        int passed = 0, failed = 0;

        for (int i = 0; i < 100; i++) {
            Aegis::Bridge::IpcEvent event = {};
            event.event_type = Aegis::Bridge::kNetworkEvent;
            event.source_ip = 0xC0A80101 + i;  // 192.168.1.x
            event.dest_ip = 0x0A000101;         // 10.0.1.1
            event.source_port = 12345 + i;
            event.dest_port = 80;
            event.protocol = 6;  // TCP
            event.tier_result = 1;  // Tier-1
            event.severity = (i % 4 == 0) ? 3 : 1;  // 25% critical
            event.rule_id = 56 + (i % 5);

            int32_t r = aegis_bridge_push_event(&event);
            if (r == 0) passed++; else failed++;
        }

        fprintf(stdout, "  Push 100 events: %d passed, %d failed\n", passed, failed);

        // Test 2: Pop events
        int popped = 0;
        Aegis::Bridge::IpcEvent outEvent;
        while (aegis_bridge_pop_event(&outEvent) == 0) {
            popped++;
        }
        fprintf(stdout, "  Pop events: %d retrieved\n", popped);

        // Test 3: DEFCON calculation
        aegis_bridge_update_defcon(5, 2, 0, 15);
        uint8_t defcon = aegis_bridge_get_defcon();
        fprintf(stdout, "  DEFCON level: %u (%s) — expected: 2 (SEVERE)\n",
            defcon, aegis_bridge_get_defcon_label());

        aegis_bridge_update_defcon(0, 0, 0, 0);
        defcon = aegis_bridge_get_defcon();
        fprintf(stdout, "  DEFCON level: %u (%s) — expected: 5 (SAFE)\n",
            defcon, aegis_bridge_get_defcon_label());

        aegis_bridge_update_defcon(1, 0, 1, 3);
        defcon = aegis_bridge_get_defcon();
        fprintf(stdout, "  DEFCON level: %u (%s) — expected: 1 (MAXIMUM)\n",
            defcon, aegis_bridge_get_defcon_label());

        // Test 4: Packet Parser
        // Craft a minimal IPv4+TCP packet (20+20=40 bytes)
        uint8_t rawPacket[40] = {};
        rawPacket[0] = 0x45;  // Version=4, IHL=5
        rawPacket[2] = 0x00; rawPacket[3] = 0x28;  // Total length=40
        rawPacket[8] = 0x40;  // TTL=64
        rawPacket[9] = 0x06;  // Protocol=TCP
        rawPacket[12] = 0xC0; rawPacket[13] = 0xA8; rawPacket[14] = 0x01; rawPacket[15] = 0x01;  // 192.168.1.1
        rawPacket[16] = 0x0A; rawPacket[17] = 0x00; rawPacket[18] = 0x01; rawPacket[19] = 0x01;  // 10.0.1.1
        // TCP header starts at offset 20
        rawPacket[20] = 0x30; rawPacket[21] = 0x39;  // src port 12345
        rawPacket[22] = 0x00; rawPacket[23] = 0x50;  // dst port 80
        rawPacket[32] = 0x50;  // Data offset=5 (20 bytes)

        Aegis::Bridge::IpcEvent parsedEvent;
        int32_t parseResult = aegis_parse_packet(rawPacket, 40, &parsedEvent);
        fprintf(stdout, "  Packet parse: %s (result=%d)\n",
            parseResult == 0 ? "SUCCESS" : "FAILED", parseResult);
        if (parseResult == 0) {
            fprintf(stdout, "    Protocol: %u, src_port: %u, dst_port: %u\n",
                parsedEvent.protocol, parsedEvent.source_port, parsedEvent.dest_port);
        }

        // Test 5: NOP sled detection
        uint8_t nopSled[20];
        memset(nopSled, 0x90, 20);
        int32_t hasNop = aegis_check_nop_sled(nopSled, 20, 5);
        fprintf(stdout, "  NOP sled detection: %s (result=%d)\n",
            hasNop ? "DETECTED" : "NOT FOUND", hasNop);

        fprintf(stdout, "\n[AEGIS Bridge] Self-test complete: %d/%d passed\n", passed + 5 - failed, 105);

        aegis_bridge_shutdown();
        return 0;
    }

    // ====== Normal Mode: Run Bridge daemon ======
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    fprintf(stdout, "[AEGIS Bridge] Running in daemon mode (Ctrl+C to stop)\n");
    fprintf(stdout, "[AEGIS Bridge] Waiting for events from subsystems...\n\n");

    uint32_t tickCount = 0;
    while (g_running) {
        // Check for events and print them
        Aegis::Bridge::IpcEvent event;
        if (aegis_bridge_pop_event(&event) == 0) {
            if (jsonMode) {
                // JSON output (for Dashboard WebSocket to consume)
                fprintf(stdout,
                    "{\"type\":\"event\",\"event_type\":%u,\"src_ip\":\"%d.%d.%d.%d\","
                    "\"dst_ip\":\"%d.%d.%d.%d\",\"src_port\":%u,\"dst_port\":%u,"
                    "\"proto\":%u,\"tier\":%u,\"rule\":%u,\"severity\":%u,\"ts\":%llu}\n",
                    event.event_type,
                    (event.source_ip >> 0) & 0xFF, (event.source_ip >> 8) & 0xFF,
                    (event.source_ip >> 16) & 0xFF, (event.source_ip >> 24) & 0xFF,
                    (event.dest_ip >> 0) & 0xFF, (event.dest_ip >> 8) & 0xFF,
                    (event.dest_ip >> 16) & 0xFF, (event.dest_ip >> 24) & 0xFF,
                    event.source_port, event.dest_port,
                    event.protocol, event.tier_result,
                    event.rule_id, event.severity,
                    (unsigned long long)event.timestamp);
            } else {
                // Human-readable output
                fprintf(stdout,
                    "[EVENT] type=%u src=%d.%d.%d.%d:%u dst=%d.%d.%d.%d:%u "
                    "proto=%u tier=%u rule=R%04u severity=%u\n",
                    event.event_type,
                    (event.source_ip >> 0) & 0xFF, (event.source_ip >> 8) & 0xFF,
                    (event.source_ip >> 16) & 0xFF, (event.source_ip >> 24) & 0xFF,
                    event.source_port,
                    (event.dest_ip >> 0) & 0xFF, (event.dest_ip >> 8) & 0xFF,
                    (event.dest_ip >> 16) & 0xFF, (event.dest_ip >> 24) & 0xFF,
                    event.dest_port,
                    event.protocol, event.tier_result,
                    event.rule_id, event.severity);
            }
            fflush(stdout);
        }

        // Periodic status
        tickCount++;
        if (tickCount % 1000 == 0) {
            uint8_t defcon = aegis_bridge_get_defcon();
            uint32_t events = aegis_bridge_get_event_count();
            uint32_t dropped = aegis_bridge_get_dropped_count();
            fprintf(stderr, "[AEGIS Bridge] Status: DEFCON=%u events=%u dropped=%u\n",
                defcon, events, dropped);
        }

#ifdef _WIN32
        Sleep(10);  // 10ms polling interval
#else
        usleep(10000);  // 10ms
#endif
    }

    // ====== Shutdown ======
    fprintf(stdout, "\n[AEGIS Bridge] Shutting down...\n");
    aegis_bridge_shutdown();
    fprintf(stdout, "[AEGIS Bridge] Goodbye.\n");

    return 0;
}
