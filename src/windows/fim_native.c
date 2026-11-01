/* II02 - FIM Native Helper (C side)
 * AEGIS NIDS v5.0+ â€” ReadDirectoryChangesW with completion routines.
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define AEGIS_FIM_BUFFER_SIZE (64 * 1024)

/* FIM-LONGPATH-044: NT extended-length path support. Win32 file APIs
 * cap at MAX_PATH (260) unless the path carries the \\?\ prefix (limit
 * 32767 wide chars). Deep watch trees (Program Files subtrees, user
 * profiles) exceed 260 and previously truncated silently into
 * CreateFileW failure. Convert UTF-8 strictly (invalid sequences fail
 * closed instead of best-fit mapping) and prefix absolute paths. */
#define FIM_PATH_WCHARS 32768

static int fim_to_wide(const char* path, wchar_t* out, size_t out_wchars) {
    /* Heap scratch: 64 KiB would be rude on the watcher's stack. */
    wchar_t* rest = (wchar_t*)malloc(FIM_PATH_WCHARS * sizeof(wchar_t));
    int n;
    int rc = -1;
    size_t plen;
    if (!path || !out || out_wchars < 8 || !rest) goto done;
    plen = strlen(path);
    if (plen == 0) goto done;
    /* Already extended-length: pass through verbatim. */
    if (plen >= 4 &&
        ((path[0] == '\\' && path[1] == '\\' && path[2] == '?' && path[3] == '\\') ||
         (path[0] == '/' && path[1] == '/' && path[2] == '?' && path[3] == '/'))) {
        n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, out, (int)out_wchars);
        rc = (n > 0) ? 0 : -1;
        goto done;
    }
    /* UNC \\host\share -> \\?\UNC\host\share */
    if (plen >= 3 &&
        ((path[0] == '\\' && path[1] == '\\') || (path[0] == '/' && path[1] == '/'))) {
        n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path + 2, -1, rest, FIM_PATH_WCHARS);
        if (n <= 0) goto done;
        rc = (_snwprintf(out, out_wchars, L"\\\\?\\UNC\\%ls", rest) < 0) ? -1 : 0;
        goto done;
    }
    /* Absolute drive path X:\... (either slash) -> \\?\X:\... */
    if (plen >= 3 &&
        ((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) &&
        path[1] == ':' && (path[2] == '\\' || path[2] == '/')) {
        n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, rest, FIM_PATH_WCHARS);
        if (n <= 0) goto done;
        rc = (_snwprintf(out, out_wchars, L"\\\\?\\%ls", rest) < 0) ? -1 : 0;
        goto done;
    }
    /* Relative path: no prefix possible; converts strictly, length capped
     * by the Win32 relative limit naturally (CreateFileW fails closed). */
    n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, out, (int)out_wchars);
    rc = (n > 0) ? 0 : -1;
done:
    free(rest);
    return rc;
}

typedef struct {
    HANDLE dir_handle;
    OVERLAPPED overlapped;
    uint8_t buffer[AEGIS_FIM_BUFFER_SIZE];
    BOOL recursive;
    DWORD filter;
    HANDLE thread;
    HANDLE event;
    CRITICAL_SECTION lock;
    DWORD bytes_ready;
    BOOL data_ready;
    volatile LONG running;
} aegis_fim_session_t;

static DWORD WINAPI fim_thread(LPVOID arg) {
    aegis_fim_session_t* s = (aegis_fim_session_t*)arg;
    for (;;) {
        DWORD bytes_returned = 0;
        DWORD read_error = ERROR_SUCCESS;

        /* Serialize the running check and I/O submission with stop().
         * Otherwise stop can cancel before this request exists, after which
         * this worker could submit an uncancelled read and outlive its session. */
        EnterCriticalSection(&s->lock);
        if (!InterlockedCompareExchange(&s->running, 1, 1)) {
            LeaveCriticalSection(&s->lock);
            break;
        }
        while (s->data_ready && InterlockedCompareExchange(&s->running, 1, 1)) {
            LeaveCriticalSection(&s->lock);
            Sleep(10);
            EnterCriticalSection(&s->lock);
        }
        if (!InterlockedCompareExchange(&s->running, 1, 1)) {
            LeaveCriticalSection(&s->lock);
            break;
        }
        if (!ResetEvent(s->event)) {
            DWORD error = GetLastError();
            LeaveCriticalSection(&s->lock);
            fprintf(stderr, "[FIM] ResetEvent failed: %lu\n", error);
            break;
        }
        memset(&s->overlapped, 0, sizeof(OVERLAPPED));
        s->overlapped.hEvent = s->event;
        BOOL ok = ReadDirectoryChangesW(
            s->dir_handle, s->buffer, AEGIS_FIM_BUFFER_SIZE,
            s->recursive, s->filter, NULL, &s->overlapped, NULL);
        if (!ok) read_error = GetLastError();
        LeaveCriticalSection(&s->lock);

        if (!ok && read_error != ERROR_IO_PENDING) {
            if (InterlockedCompareExchange(&s->running, 1, 1))
                fprintf(stderr, "[FIM] ReadDirectoryChangesW failed: %lu\n", read_error);
            break;
        }
        DWORD wait_result = WaitForSingleObject(s->overlapped.hEvent, INFINITE);
        if (wait_result != WAIT_OBJECT_0) {
            DWORD error = (wait_result == WAIT_FAILED) ? GetLastError() : ERROR_INVALID_DATA;
            fprintf(stderr, "[FIM] overlapped event wait failed: result=%lu error=%lu\n",
                    wait_result, error);
            break;
        }
        if (!GetOverlappedResult(s->dir_handle, &s->overlapped, &bytes_returned, FALSE)) {
            DWORD error = GetLastError();
            if (InterlockedCompareExchange(&s->running, 1, 1)) {
                fprintf(stderr, "[FIM] GetOverlappedResult failed: %lu\n", error);
            }
            continue;
        }
        if (bytes_returned == 0) continue;
        EnterCriticalSection(&s->lock);
        s->bytes_ready = bytes_returned;
        s->data_ready = TRUE;
        LeaveCriticalSection(&s->lock);
    }
    return 0;
}

void* aegis_fim_start(const char* path, uint32_t recursive, uint32_t filter) {
    /* Heap buffer: extended-length paths reach 32767 wide chars. */
    wchar_t* wpath = (wchar_t*)malloc(FIM_PATH_WCHARS * sizeof(wchar_t));
    if (!wpath) return NULL;
    if (fim_to_wide(path, wpath, FIM_PATH_WCHARS) != 0) {
        fprintf(stderr, "[FIM] path conversion failed (invalid UTF-8 or oversize)\n");
        free(wpath);
        return NULL;
    }
    HANDLE h = CreateFileW(wpath, FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[FIM] CreateFileW failed for %ls: error=%lu\\n", wpath, GetLastError());
        free(wpath);
        return NULL;
    }

    aegis_fim_session_t* s = (aegis_fim_session_t*)calloc(1, sizeof(aegis_fim_session_t));
    if (!s) { CloseHandle(h); free(wpath); return NULL; }
    s->dir_handle = h;
    s->recursive = recursive ? TRUE : FALSE;
    s->filter = filter;
    s->event = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!s->event) {
        fprintf(stderr, "[FIM] CreateEvent failed for %ls: error=%lu\\n", wpath, GetLastError());
        CloseHandle(h);
        free(s);
        free(wpath);
        return NULL;
    }
    InitializeCriticalSection(&s->lock);
    s->bytes_ready = 0;
    s->data_ready = FALSE;
    InterlockedExchange(&s->running, 1);
    s->thread = CreateThread(NULL, 0, fim_thread, s, 0, NULL);
    if (!s->thread) {
        fprintf(stderr, "[FIM] CreateThread failed for %ls: error=%lu\\n", wpath, GetLastError());
        CloseHandle(h);
        CloseHandle(s->event);
        DeleteCriticalSection(&s->lock);
        free(s);
        free(wpath);
        return NULL;
    }
    free(wpath);
    return (void*)s;
}

int aegis_fim_stop(void* handle) {
    aegis_fim_session_t* s = (aegis_fim_session_t*)handle;
    if (!s) return -1;

    /* Use the same lock as read submission so cancellation cannot happen
     * just before the worker starts a new request. */
    EnterCriticalSection(&s->lock);
    InterlockedExchange(&s->running, 0);
    BOOL cancel_ok = CancelIoEx(s->dir_handle, NULL);
    DWORD cancel_error = cancel_ok ? ERROR_SUCCESS : GetLastError();
    LeaveCriticalSection(&s->lock);
    if (!cancel_ok && cancel_error != ERROR_NOT_FOUND) {
        fprintf(stderr, "[FIM] CancelIoEx failed: %lu; waiting for worker before release\n",
                cancel_error);
    }

    /* Never free session memory while the native worker may still reference
     * it. Cancellation completion wakes the worker's event wait. */
    DWORD wait_result = WaitForSingleObject(s->thread, INFINITE);
    if (wait_result != WAIT_OBJECT_0) {
        DWORD error = (wait_result == WAIT_FAILED) ? GetLastError() : ERROR_INVALID_DATA;
        fprintf(stderr, "[FIM] worker did not signal termination: result=%lu error=%lu; session retained\n",
                wait_result, error);
        return -2;
    }
    CloseHandle(s->thread);
    CloseHandle(s->dir_handle);
    CloseHandle(s->event);
    DeleteCriticalSection(&s->lock);
    free(s);
    return 0;
}

int aegis_fim_poll(void* handle, uint8_t* out_buf, size_t out_len) {
    aegis_fim_session_t* s = (aegis_fim_session_t*)handle;
    if (!s) return -1;
    EnterCriticalSection(&s->lock);
    if (!s->data_ready) {
        LeaveCriticalSection(&s->lock);
        return 0;
    }
    DWORD bytes = s->bytes_ready;
    if (bytes > 0 && bytes <= out_len) memcpy(out_buf, s->buffer, bytes);
    s->data_ready = FALSE;
    s->bytes_ready = 0;
    LeaveCriticalSection(&s->lock);
    /* Tripwire, not silent loss: with matched 64 KiB buffers this is
     * unreachable, but any future size drift must surface as -2
     * (truncated) instead of 0 (no data). */
    if (bytes > out_len) return -2;
    return (bytes > 0) ? (int)bytes : 0;
}
