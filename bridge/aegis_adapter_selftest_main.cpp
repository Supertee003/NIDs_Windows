// aegis_adapter_selftest_main.cpp - standalone smoke test for the C ABI.
#include "aegis_adapter.hpp"
#include <cstdio>
#include <cstring>

int main() {
    void* reg = aegis_adapter_registry_create();
    if (!reg) { fprintf(stderr, "FAIL: registry create\n"); return 1; }

    // Start all four adapters.
    void* handles[4];
    const uint8_t kinds[4] = { 1, 2, 3, 4 }; // Etw, Fim, Registry, Process
    const char* names[4] = { "etw", "fim", "registry", "process" };
    for (int i = 0; i < 4; ++i) {
        handles[i] = aegis_adapter_start(reg, kinds[i]);
        if (!handles[i]) { fprintf(stderr, "FAIL: start %s\n", names[i]); return 2; }
    }

    // Poll each once.
    uint8_t buf[32 * 109];
    for (int i = 0; i < 4; ++i) {
        uint8_t out[8];
        uint32_t per = 0;
        int32_t n = aegis_adapter_poll(handles[i], out, 8, buf, sizeof(buf), &per);
        fprintf(stdout, "%s poll -> %d events, bytes/ev=%u\n", names[i], (int)n, per);
        if (n > 0) {
            if (per != 109) { fprintf(stderr, "FAIL: %s wire size %u\n", names[i], per); return 3; }
            // magic "AEG1" -> 31 47 45 41
            if (buf[0] != 0x31 || buf[3] != 0x41) {
                fprintf(stderr, "FAIL: %s magic\n", names[i]); return 4;
            }
        }
    }

    // Health check.
    for (int i = 0; i < 4; ++i) {
        uint8_t st; uint32_t le; uint64_t prod;
        aegis_adapter_health(handles[i], &st, &le, &prod);
        fprintf(stdout, "%s health state=%u err=%u produced=%llu\n",
                names[i], (unsigned)st, (unsigned)le, (unsigned long long)prod);
    }

    aegis_adapter_registry_destroy(reg);
    fprintf(stdout, "adapter selftest OK\n");
    return 0;
}