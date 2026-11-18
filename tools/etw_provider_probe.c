/* etw_provider_probe.c - GAP-012 bullet 5 runtime proof (EVT-114).
 *
 * Calls aegis_etw_start() from the canonical helper DLL twice:
 *   1. bogus GUID  -> must refuse ready with rc -6, creating no session.
 *   2. three registered kernel GUIDs -> must PASS validation (rc 0 when
 *      elevated with a working session, or a StartTraceW status otherwise;
 *      anything EXCEPT -6/-7 proves the GUIDs are host-registered).
 *
 * Needs no elevation for case 1 (validation precedes every session call).
 * Case 2 needs an elevated prompt for the full start; without elevation a
 * nonzero non -6/-7 status still proves registration (validation passed,
 * session creation refused by privilege, honestly reported).
 *
 * GUID bytes below are the Windows memory layout (Data1/Data2/Data3
 * little-endian) pinned by EVT-091 logman ground truth:
 *   Process  {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
 *   File     {EDD08927-9CC4-4E65-B970-C2560FB5C289}
 *   Registry {70EB4F03-C1DE-4F73-A051-33D13D5413BD}
 *
 * Build with MSVC (canonical C toolchain; the mingw headers lack
 * PROCESSTRACE_HANDLE so this file is MSVC-only by design):
 *   cl /nologo /W4 /utf-8 tools\\etw_provider_probe.c ^
 *      /link target\\helpers\\aegis_etw_helper.lib
 * Run:
 *   .\\etw_provider_probe.exe
 * Exit code 0 = both expectations hold; nonzero = finding to investigate.
 *
 * This file is intentionally NOT referenced by CMakeLists.txt, build.zig,
 * or any test runner: it is an operator-run proof harness, not a build
 * product. Keep it that way.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

__declspec(dllimport) int aegis_etw_start(const char *session_name,
                                          const uint8_t (*providers)[16],
                                          size_t provider_count);
__declspec(dllimport) int aegis_etw_stop(const char *session_name);

static const uint8_t BOGUS_GUID[16] = {
    0xEF, 0xBE, 0xAD, 0xDE, 0xAD, 0xDE, 0xEF, 0xBE,
    0xDE, 0xAD, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD,
};

static const uint8_t REGISTERED_GUIDS[3][16] = {
    {0xD6, 0x2C, 0xFB, 0x22, 0x7B, 0x0E, 0x2B, 0x42,
     0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16},
    {0x27, 0x89, 0xD0, 0xED, 0xC4, 0x9C, 0x65, 0x4E,
     0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89},
    {0x03, 0x4F, 0xEB, 0x70, 0xDE, 0xC1, 0x73, 0x4F,
     0xA0, 0x51, 0x33, 0xD1, 0x3D, 0x54, 0x13, 0xBD},
};

int main(void) {
    int failures = 0;

    /* Case 1: unregistered GUID must refuse ready with rc -6. */
    {
        uint8_t providers[1][16];
        memcpy(providers, BOGUS_GUID, 16);
        int rc = aegis_etw_start("AEGIS-PROBE", providers, 1);
        if (rc == -6) {
            printf("[PASS] bogus GUID refused ready (rc -6), no session created\n");
        } else {
            printf("[FAIL] bogus GUID returned rc %d, want -6\n", rc);
            failures++;
        }
    }

    /* Case 2: registered GUIDs must pass validation (rc anything but -6/-7). */
    {
        int rc = aegis_etw_start("AEGIS-PROBE", REGISTERED_GUIDS, 3);
        if (rc == -6 || rc == -7) {
            printf("[FAIL] registered GUIDs failed validation (rc %d)\n", rc);
            failures++;
        } else {
            printf("[PASS] registered GUIDs passed validation (rc %d)", rc);
            if (rc == 0) {
                printf(" — session started, stopping it\n");
                aegis_etw_stop("AEGIS-PROBE");
            } else {
                printf(" — session not started (status %d, expected without elevation)\n", rc);
            }
        }
    }

    if (failures == 0) {
        printf("PROBE OK: provider pre-validation behaves as specified\n");
        return 0;
    }
    printf("PROBE FAILED: %d case(s)\n", failures);
    return 1;
}
