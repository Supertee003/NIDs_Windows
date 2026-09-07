/* II02 - FIM Native Helper (C side)
 * AEGIS NIDS v5.0+ â€” ReadDirectoryChangesW with completion routines.
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define AEGIS_FIM_BUFFER_SIZE (64 * 1024)

typedef struct {
    HANDLE dir_handle;
    OVERLAPPED overlapped;
    uint8_t buffer[AEGIS_FIM_BUFFER_SIZE];
    BOOL recursive;
    DWORD filter;
    HANDLE thread;
    volatile LONG running;
} aegis_fim_session_t;

static DWORD WINAPI fim_thread(LPVOID arg) {
    aegis_fim_session_t* s = (aegis_fim_session_t*)arg;
    while (InterlockedCompareExchange(&s->running, 1, 1)) {
        DWORD bytes_returned = 0;
        memset(&s->overlapped, 0, sizeof(OVERLAPPED));
        s->overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        BOOL ok = ReadDirectoryChangesW(
            s->dir_handle, s->buffer, AEGIS_FIM_BUFFER_SIZE,
            s->recursive, s->filter, &bytes_returned, &s->overlapped, NULL);
        if (!ok) break;
        WaitForSingleObject(s->overlapped.hEvent, INFINITE);
        CloseHandle(s->overlapped.hEvent);
        if (bytes_returned == 0) continue;
        /* Note: actual events are stored in s->buffer; caller polls. */
    }
    return 0;
}

void* aegis_fim_start(const char* path, uint32_t recursive, uint32_t filter) {
    wchar_t wpath[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, MAX_PATH);
    HANDLE h = CreateFileW(wpath, FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;

    aegis_fim_session_t* s = (aegis_fim_session_t*)calloc(1, sizeof(aegis_fim_session_t));
    if (!s) { CloseHandle(h); return NULL; }
    s->dir_handle = h;
    s->recursive = recursive ? TRUE : FALSE;
    s->filter = filter;
    InterlockedExchange(&s->running, 1);
    s->thread = CreateThread(NULL, 0, fim_thread, s, 0, NULL);
    if (!s->thread) {
        CloseHandle(h);
        free(s);
        return NULL;
    }
    return (void*)s;
}

int aegis_fim_stop(void* handle) {
    aegis_fim_session_t* s = (aegis_fim_session_t*)handle;
    if (!s) return -1;
    InterlockedExchange(&s->running, 0);
    CancelIoEx(s->dir_handle, NULL);
    WaitForSingleObject(s->thread, 5000);
    CloseHandle(s->thread);
    CloseHandle(s->dir_handle);
    free(s);
    return 0;
}

int aegis_fim_poll(void* handle, uint8_t* out_buf, size_t out_len) {
    aegis_fim_session_t* s = (aegis_fim_session_t*)handle;
    if (!s) return -1;
    /* For simplicity, copy any bytes in the buffer; real impl walks
       FILE_NOTIFY_INFORMATION linked list and converts to a flat format. */
    DWORD bytes = 0;
    if (GetOverlappedResult(s->dir_handle, &s->overlapped, &bytes, FALSE)) {
        if (bytes > 0 && bytes <= out_len) {
            memcpy(out_buf, s->buffer, bytes);
            return (int)bytes;
        }
    }
    return 0;
}
