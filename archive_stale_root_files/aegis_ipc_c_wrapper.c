#include <windows.h>
#include <stdio.h>
#include <string.h>

static HMODULE hIpc = NULL;

typedef int (*fn_init_t)(const char*, int);
typedef int (*fn_send_t)(const char*, const char*, int);
typedef int (*fn_recv_t)(char*, int);
typedef int (*fn_status_t)(void);
typedef void (*fn_shutdown_t)(void);
typedef int (*fn_get_stats_t)(void);

static fn_init_t p_init = NULL;
static fn_send_t p_send = NULL;
static fn_recv_t p_recv = NULL;
static fn_status_t p_status = NULL;
static fn_shutdown_t p_shutdown = NULL;
static fn_get_stats_t p_get_stats = NULL;

static int stats_packets = 0;
static int stats_alerts = 0;

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD fdwReason, LPVOID lpvReserved) {
    (void)hInst; (void)lpvReserved;
    if (fdwReason == DLL_PROCESS_ATTACH) {
        hIpc = LoadLibraryA("aegis_ipc.dll");
        if (hIpc) {
            p_init = (fn_init_t)GetProcAddress(hIpc, "aegis_ipc_init");
            p_send = (fn_send_t)GetProcAddress(hIpc, "aegis_ipc_send");
            p_recv = (fn_recv_t)GetProcAddress(hIpc, "aegis_ipc_recv");
            p_status = (fn_status_t)GetProcAddress(hIpc, "aegis_ipc_status");
            p_shutdown = (fn_shutdown_t)GetProcAddress(hIpc, "aegis_ipc_shutdown");
            p_get_stats = (fn_get_stats_t)GetProcAddress(hIpc, "aegis_ipc_get_stats");
        }
    } else if (fdwReason == DLL_PROCESS_DETACH) {
        if (hIpc) FreeLibrary(hIpc);
    }
    return TRUE;
}

__declspec(dllexport) int aegis_ipc_init(const char* cfg, int port) {
    if (p_init) return p_init(cfg, port);
    printf("[IPC-C] init: port=%d\n", port);
    return 0;
}

__declspec(dllexport) int aegis_ipc_send(const char* ch, const char* data, int len) {
    stats_packets++;
    if (p_send) return p_send(ch, data, len);
    return len;
}

__declspec(dllexport) int aegis_ipc_recv(char* buf, int len) {
    if (p_recv) return p_recv(buf, len);
    if (buf && len > 0) buf[0] = 0;
    return 0;
}

__declspec(dllexport) int aegis_ipc_status(void) {
    if (p_status) return p_status();
    return hIpc ? 1 : 0;
}

__declspec(dllexport) void aegis_ipc_shutdown(void) {
    if (p_shutdown) p_shutdown();
}

__declspec(dllexport) int aegis_ipc_get_stats(void) {
    if (p_get_stats) return p_get_stats();
    /* Stub: return combined counter */
    return stats_packets + stats_alerts;
}
