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
 *   ./aegis_bridge --version    # Print version + exit (Gate-A conformance)
 */

#include "aegis_ipc.hpp"
#include "aegis_packet_parser.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <thread>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <unistd.h>
#include <signal.h>
#include <time.h>
#endif

// ====== AEGIS version constant (single source of truth) ======
// Bumped on every release. Parsed by tests/runtime/test_version.py via
// the SEMVER pattern (major.minor.patch with optional -suffix).
#define AEGIS_BRIDGE_VERSION "1.0.0"

static volatile bool g_running = true;

// ====== Health-check named pipe (§4 / §4.1 of RUNTIME_CONTRACT.md) ======
// Exposes `\\.\pipe\aegis-bridge-health` so the supervisor and the runtime
// tests can probe the lifecycle state without spawning a child process.
#ifdef _WIN32
static const char* kHealthPipeName = "\\\\.\\pipe\\aegis-bridge-health";
#endif

static unsigned long long g_start_ms = 0;

static unsigned long long now_monotonic_ms() {
#ifdef _WIN32
    return (unsigned long long)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000u
         + (unsigned long long)(ts.tv_nsec / 1000000);
#endif
}

// Runs on a detached thread. Serves one health probe at a time on a
// single-instance message-mode pipe, then recreates the pipe for the
// next probe. The process kills this thread on exit (daemon semantics).
static void health_server_routine() {
#ifdef _WIN32
    while (g_running) {
        HANDLE hPipe = CreateNamedPipeA(
            kHealthPipeName,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            4096, 4096,
            0, NULL);
        if (hPipe == INVALID_HANDLE_VALUE) {
            Sleep(50);
            continue;
        }

        if (g_running) {
            BOOL connected = ConnectNamedPipe(hPipe, NULL);
            if (!connected && GetLastError() != ERROR_PIPE_CONNECTED) {
                CloseHandle(hPipe);
                continue;
            }
        }
        if (!g_running) {
            CloseHandle(hPipe);
            break;
        }

        DWORD bytesRead = 0;
        char request[256] = {0};
        ReadFile(hPipe, request, sizeof(request) - 1, &bytesRead, NULL);

        unsigned long long probe_start = now_monotonic_ms();
        char response[512];
        int n = snprintf(response, sizeof(response),
            "{\"op\":\"HEALTH\",\"state\":\"RUNNING\",\"status\":\"OK\","
            "\"component\":\"bridge\",\"subsystem\":\"bridge\","
            "\"version\":\"" AEGIS_BRIDGE_VERSION "\","
            "\"pid\":%lu,\"uptime_ms\":%llu,\"probe_latency_ms\":%llu}",
            (unsigned long)GetCurrentProcessId(),
            now_monotonic_ms() - g_start_ms,
            now_monotonic_ms() - probe_start);

        DWORD bytesWritten = 0;
        WriteFile(hPipe, response, (DWORD)n, &bytesWritten, NULL);
        FlushFileBuffers(hPipe);
        CloseHandle(hPipe);
    }
#endif
}

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
        // G27 Gate-A: --version flag. Prints SEMVER and exits 0 so the
        // supervisor (and tests/runtime/test_version.py) can verify the
        // binary is present and reports a parseable version.
        if (strcmp(argv[i], "--version") == 0) {
            printf("aegis-bridge %s\n", AEGIS_BRIDGE_VERSION);
            return 0;
        }
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "-V") == 0) {
            printf("aegis-bridge %s\n", AEGIS_BRIDGE_VERSION);
            return 0;
        }
    }

    // ====== Set console to UTF-8 (fixes box-drawing mojibake on Windows) ======
#ifdef _WIN32
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);
#endif

    // ====== Banner (64-char wide, ANSI colored) ======
    const char* RST = "\x1b[0m";
    const char* BLD = "\x1b[1m";
    const char* CYN = "\x1b[96m";
    const char* GRN = "\x1b[92m";
    const char* YEL = "\x1b[93m";
    const char* DIM = "\x1b[2m";

    fprintf(stdout, "\n");
    fprintf(stdout, "%s╔════════════════════════════════════════════════════════════╗%s\n", CYN, RST);
    fprintf(stdout, "%s║%s %sAEGIS NIDS — IPC Bridge (C++)%s %sv2.0%s                %s║%s\n", CYN, RST, BLD, RST, DIM, RST, CYN, RST);
    fprintf(stdout, "%s║%s %sMulti-Language Hybrid Architecture — Event Queue Hub%s  %s║%s\n", CYN, RST, DIM, RST, CYN, RST);
    fprintf(stdout, "%s╠════════════════════════════════════════════════════════════╣%s\n", CYN, RST);
    fprintf(stdout, "%s║%s %sZig Core%s · %sPython Brain%s · %sRust Shield%s · %sGo Nose%s  %s║%s\n", CYN, RST, GRN, RST, GRN, RST, GRN, RST, GRN, RST, CYN, RST);
    fprintf(stdout, "%s╚════════════════════════════════════════════════════════════╝%s\n", CYN, RST);
    fprintf(stdout, "\n");

    // ====== Initialize Bridge ======
    g_start_ms = now_monotonic_ms();
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

    // ====== Health-check server (named pipe, Gate-A) ======
    std::thread healthThread(health_server_routine);
    healthThread.detach();

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
