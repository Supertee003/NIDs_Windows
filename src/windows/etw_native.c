/* II01 - ETW Native Helper (C side)
 * AEGIS NIDS v5.0+
 *
 * Calls StartTraceW / ProcessTrace / EnableTraceEx2 against kernel + user-mode
 * providers. Buffers events in a per-session ring and invokes the registered
 * callback when an event is flushed.
 */

#include <windows.h>
#include <tdh.h>
#include <evntrace.h>
#include <evntcons.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define AEGIS_ETW_BUFFER_SIZE (256 * 1024)

typedef struct {
    uint32_t event_id;
    uint8_t provider_guid[16];
    uint8_t version;
    uint8_t channel;
    uint8_t level;
    uint8_t opcode;
    uint16_t task;
    uint64_t keyword;
    int64_t timestamp_ns;
    uint32_t process_id;
    uint32_t thread_id;
    uint64_t image_base;
    uint32_t image_size;
    uint16_t ext_data_len;
    uint32_t ext_data_offset;
} aegis_etw_event_t;

typedef void (*aegis_etw_cb_t)(void* ctx, const aegis_etw_event_t* rec,
                                const uint8_t* ext_data, size_t ext_len);

typedef struct {
    TRACEHANDLE session_handle;
    volatile LONG64 consumer_handle;
    EVENT_TRACE_PROPERTIES* properties;
    wchar_t session_name[64];
    aegis_etw_cb_t callback;
    void* callback_ctx;
    volatile LONG running;
    HANDLE consumer_thread;
    HANDLE consumer_ready_event;
    uint8_t ext_buffer[AEGIS_ETW_BUFFER_SIZE];
} aegis_etw_session_t;

static aegis_etw_session_t g_session;
/* Static initialization keeps callback synchronization valid across restart. */
static SRWLOCK g_lock = SRWLOCK_INIT;
static SRWLOCK g_lifecycle_lock = SRWLOCK_INIT;

/* GAP-012 bullet 5: refuse ready for non-registered provider GUIDs.
 * EnableTraceEx2 succeeds silently for a GUID no provider registered, so
 * membership must be checked before the session exists. A size query
 * against the provider manifest is enough: registered -> the API reports
 * the required buffer (or success); not registered -> ERROR_NOT_FOUND.
 * Any other status is inconclusive and fails closed (rc -7) rather than
 * risking another silent-loss session. Returns 1 registered, 0 not
 * registered, -1 inconclusive. */
static int provider_is_registered(const uint8_t guid_bytes[16]) {
    GUID guid;
    memcpy(&guid, guid_bytes, sizeof(guid));
    ULONG size = 0;
    ULONG status = TdhEnumerateManifestProviderEvents(&guid, NULL, &size);
    if (status == ERROR_NOT_FOUND) return 0;
    if (status == ERROR_SUCCESS || status == ERROR_INSUFFICIENT_BUFFER) return 1;
    fprintf(stderr, "[ETW] provider metadata query inconclusive: status=%lu\n", status);
    return -1;
}

#define AEGIS_ETW_TLV_MAGIC 0x54474541u /* "AEGT" little-endian */
#define AEGIS_ETW_TLV_IMAGE 1
#define AEGIS_ETW_TLV_CMDLINE 2
#define AEGIS_ETW_TLV_FILE 3
#define AEGIS_ETW_TLV_REGISTRY 4
#define AEGIS_ETW_TLV_PARENT_PID 5

static int append_tlv(uint16_t kind, const uint8_t* data, uint16_t len, uint16_t* used) {
    if (data == NULL || used == NULL || (size_t)*used + 4u + len > AEGIS_ETW_BUFFER_SIZE ||
        (size_t)*used + 4u + len > UINT16_MAX) return 0;
    uint8_t* dst = g_session.ext_buffer + *used;
    memcpy(dst, &kind, sizeof(kind));
    memcpy(dst + 2, &len, sizeof(len));
    memcpy(dst + 4, data, len);
    *used = (uint16_t)(*used + 4u + len);
    return 1;
}

static void append_property_utf8(PEVENT_RECORD rec, LPCWSTR property, uint16_t kind, uint16_t* used) {
    PROPERTY_DATA_DESCRIPTOR desc = {0};
    desc.PropertyName = (ULONGLONG)(ULONG_PTR)property;
    ULONG size = 0;
    if (TdhGetPropertySize(rec, 0, NULL, 1, &desc, &size) != ERROR_SUCCESS || size == 0 || size > 4096) return;
    uint8_t raw[4096];
    if (TdhGetProperty(rec, 0, NULL, 1, &desc, size, raw) != ERROR_SUCCESS) return;
    int wide_len = (int)(size / sizeof(wchar_t));
    while (wide_len > 0 && ((wchar_t*)raw)[wide_len - 1] == L'\0') wide_len--;
    if (wide_len <= 0) return;
    int out_len = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                                      (const wchar_t*)raw, wide_len, NULL, 0, NULL, NULL);
    if (out_len <= 0 || out_len > 4096) return;
    uint8_t out[4096];
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                            (const wchar_t*)raw, wide_len, (char*)out, out_len, NULL, NULL) <= 0) return;
    append_tlv(kind, out, (uint16_t)out_len, used);
}

static void append_property_u32(PEVENT_RECORD rec, LPCWSTR property, uint16_t kind, uint16_t* used) {
    PROPERTY_DATA_DESCRIPTOR desc = {0};
    desc.PropertyName = (ULONGLONG)(ULONG_PTR)property;
    ULONG size = sizeof(uint32_t);
    uint32_t value = 0;
    if (TdhGetProperty(rec, 0, NULL, 1, &desc, size, (PBYTE)&value) == ERROR_SUCCESS) {
        append_tlv(kind, (const uint8_t*)&value, sizeof(value), used);
    }
}

static uint16_t decode_tdh_properties(PEVENT_RECORD rec) {
    uint32_t magic = AEGIS_ETW_TLV_MAGIC;
    uint16_t used = sizeof(magic);
    memcpy(g_session.ext_buffer, &magic, sizeof(magic));
    /* Names are intentionally allow-listed; unknown provider properties are ignored. */
    append_property_utf8(rec, L"ImageName", AEGIS_ETW_TLV_IMAGE, &used);
    append_property_utf8(rec, L"CommandLine", AEGIS_ETW_TLV_CMDLINE, &used);
    append_property_utf8(rec, L"FileName", AEGIS_ETW_TLV_FILE, &used);
    append_property_utf8(rec, L"KeyName", AEGIS_ETW_TLV_REGISTRY, &used);
    append_property_u32(rec, L"ParentId", AEGIS_ETW_TLV_PARENT_PID, &used);
    return used;
}

static void NTAPI event_record_callback(_In_ PEVENT_RECORD rec) {
    if (rec == NULL || rec->EventHeader.EventDescriptor.Id == 0) return;
    aegis_etw_event_t out = {0};
    out.event_id = rec->EventHeader.EventDescriptor.Id;
    memcpy(out.provider_guid, &rec->EventHeader.ProviderId, sizeof(out.provider_guid));
    out.version = rec->EventHeader.EventDescriptor.Version;
    out.channel = rec->EventHeader.EventDescriptor.Channel;
    out.level = rec->EventHeader.EventDescriptor.Level;
    out.opcode = rec->EventHeader.EventDescriptor.Opcode;
    out.task = rec->EventHeader.EventDescriptor.Task;
    out.keyword = rec->EventHeader.EventDescriptor.Keyword;
    out.timestamp_ns = (int64_t)rec->EventHeader.TimeStamp.QuadPart;
    out.process_id = rec->EventHeader.ProcessId;
    out.thread_id = rec->EventHeader.ThreadId;

    /* Decode allow-listed event properties through TDH into a bounded TLV. */
    uint16_t ext_len = decode_tdh_properties(rec);
    if (rec->ExtendedData != NULL && rec->ExtendedDataCount > 0) {
        for (USHORT i = 0; i < rec->ExtendedDataCount; i++) {
            if (rec->ExtendedData[i].ExtType == EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID) continue;
            USHORT dlen = rec->ExtendedData[i].DataSize;
            if ((size_t)ext_len + 4u + dlen > AEGIS_ETW_BUFFER_SIZE ||
                (size_t)ext_len + 4u + dlen > UINT16_MAX) break;
            /* Preserve raw extended data only as a length-delimited TLV. */
            uint16_t raw_kind = 0x7FFF;
            memcpy(g_session.ext_buffer + ext_len, &raw_kind, sizeof(raw_kind));
            memcpy(g_session.ext_buffer + ext_len + 2, &dlen, sizeof(dlen));
            memcpy(g_session.ext_buffer + ext_len + 4,
                   (const void*)(ULONG_PTR)rec->ExtendedData[i].DataPtr, dlen);
            ext_len = (uint16_t)(ext_len + 4u + dlen);
        }
    }
    out.ext_data_len = ext_len;
    out.ext_data_offset = 0;

    AcquireSRWLockExclusive(&g_lock);
    if (g_session.callback && InterlockedCompareExchange(&g_session.running, 1, 1)) {
        g_session.callback(g_session.callback_ctx, &out, g_session.ext_buffer, ext_len);
    }
    ReleaseSRWLockExclusive(&g_lock);
}

static DWORD WINAPI consumer_thread(LPVOID arg) {
    (void)arg;
    PROCESSTRACE_HANDLE trace = OpenTraceW(&((EVENT_TRACE_LOGFILEW){
        .LoggerName = g_session.session_name,
        .ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD,
        .EventRecordCallback = event_record_callback,
    }));
    if (trace == INVALID_PROCESSTRACE_HANDLE) {
        InterlockedExchange64(&g_session.consumer_handle, 0);
        if (g_session.consumer_ready_event) SetEvent(g_session.consumer_ready_event);
        return 1;
    }
    InterlockedExchange64(&g_session.consumer_handle, (LONG64)trace);
    if (g_session.consumer_ready_event) SetEvent(g_session.consumer_ready_event);
    ProcessTrace(&trace, 1, NULL, NULL);
    if (InterlockedCompareExchange64(&g_session.consumer_handle, 0, (LONG64)trace) == (LONG64)trace)
        CloseTrace(trace);
    return 0;
}

static int aegis_etw_start_impl(const char* session_name, const uint8_t (*providers)[16], size_t provider_count) {
    if (g_session.session_handle != 0) {
        fprintf(stderr, "[ETW] start rejected: session already active\\n");
        return -1;
    }
    /* ETW-STR-046: checked conversion. An unchecked MultiByteToWideChar
     * can truncate without NUL-terminating (or best-fit map invalid
     * UTF-8), handing StartTraceW a garbage session name. The Zig caller
     * passes a short constant today, but the C boundary must not trust
     * that: conversion failure fails closed before any handle exists. */
    if (!session_name || session_name[0] == '\0' ||
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, session_name, -1,
                            g_session.session_name, 64) <= 0) {
        fprintf(stderr, "[ETW] invalid session name (empty, invalid UTF-8, or too long)\\n");
        return -5;
    }
    /* GAP-012 bullet 5: validate every requested provider against host
     * registration BEFORE any session state exists, so an unknown GUID can
     * never produce a ready session with zero events. rc -6 = not
     * registered, rc -7 = registration query inconclusive (fail closed). */
    for (size_t i = 0; i < provider_count; i++) {
        int registered = provider_is_registered(providers[i]);
        if (registered == 0) {
            fprintf(stderr, "[ETW] provider %zu is not host-registered; refusing ready state\n", i);
            return -6;
        }
        if (registered < 0) {
            fprintf(stderr, "[ETW] provider %zu registration unknown; refusing ready state\n", i);
            return -7;
        }
    }
    size_t prop_size = sizeof(EVENT_TRACE_PROPERTIES) + 256 * sizeof(WCHAR);
    g_session.properties = (EVENT_TRACE_PROPERTIES*)calloc(1, prop_size);
    if (!g_session.properties) {
        fprintf(stderr, "[ETW] properties allocation failed\\n");
        return -2;
    }
    g_session.properties->Wnode.BufferSize = (ULONG)prop_size;
    g_session.properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    g_session.properties->Wnode.ClientContext = 1; // QPC
    g_session.properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    g_session.properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    g_session.properties->BufferSize = 256;
    g_session.properties->MinimumBuffers = 8;
    g_session.properties->MaximumBuffers = 32;

    ULONG status = StartTraceW(&g_session.session_handle, g_session.session_name, g_session.properties);
    if (status == ERROR_ALREADY_EXISTS) {
        // A stale session must not be treated as ours: stop it and create a
        // clean session so provider state and callback ownership are known.
        ULONG stop_status = ControlTraceW(g_session.session_handle, g_session.session_name,
                                          g_session.properties, EVENT_TRACE_CONTROL_STOP);
        fprintf(stderr, "[ETW] stale session stop status=%lu\\n", stop_status);
        g_session.session_handle = 0;
        status = StartTraceW(&g_session.session_handle, g_session.session_name, g_session.properties);
    }
    if (status != ERROR_SUCCESS) {
        fprintf(stderr, "[ETW] StartTraceW failed: status=%lu\\n", status);
        free(g_session.properties);
        g_session.properties = NULL;
        return (int)status;
    }

    size_t enabled_providers = 0;
    for (size_t i = 0; i < provider_count; i++) {
        GUID guid;
        memcpy(&guid, providers[i], 16);
        ENABLE_TRACE_PARAMETERS params = {0};
        params.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
        params.EnableProperty = EVENT_ENABLE_PROPERTY_SID | EVENT_ENABLE_PROPERTY_TS_ID |
                                  EVENT_ENABLE_PROPERTY_STACK_TRACE;
        status = EnableTraceEx2(g_session.session_handle, &guid, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                TRACE_LEVEL_VERBOSE, 0, 0, 0, &params);
        if (status != ERROR_SUCCESS) {
            fprintf(stderr, "[ETW] EnableTraceEx2 failed for provider %zu: %lu\n", i, status);
        } else {
            enabled_providers++;
        }
    }

    if (enabled_providers == 0) {
        fprintf(stderr, "[ETW] no providers enabled; refusing ready state\n");
        ULONG stop_status = ControlTraceW(g_session.session_handle, g_session.session_name,
                                          g_session.properties, EVENT_TRACE_CONTROL_STOP);
        if (stop_status == ERROR_SUCCESS || stop_status == ERROR_WMI_INSTANCE_NOT_FOUND) {
            g_session.session_handle = 0;
            free(g_session.properties);
            g_session.properties = NULL;
        } else {
            fprintf(stderr, "[ETW] cleanup after provider enable failure failed: status=%lu; retaining session state\n",
                    stop_status);
        }
        return -4;
    }

    InterlockedExchange(&g_session.running, 1);
    g_session.consumer_ready_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_session.consumer_ready_event) {
        DWORD error = GetLastError();
        InterlockedExchange(&g_session.running, 0);
        ULONG stop_status = ControlTraceW(g_session.session_handle, g_session.session_name,
                                          g_session.properties, EVENT_TRACE_CONTROL_STOP);
        if (stop_status == ERROR_SUCCESS || stop_status == ERROR_WMI_INSTANCE_NOT_FOUND) {
            g_session.session_handle = 0;
            free(g_session.properties);
            g_session.properties = NULL;
        } else {
            fprintf(stderr, "[ETW] cleanup after readiness-event failure failed: status=%lu; retaining session state\n",
                    stop_status);
        }
        fprintf(stderr, "[ETW] CreateEventW failed: error=%lu\n", error);
        return -10;
    }
    g_session.consumer_thread = CreateThread(NULL, 0, consumer_thread, NULL, 0, NULL);
    if (!g_session.consumer_thread) {
        fprintf(stderr, "[ETW] CreateThread failed: error=%lu\\n", GetLastError());
        InterlockedExchange(&g_session.running, 0);
        ULONG stop_status = ControlTraceW(g_session.session_handle, g_session.session_name,
                                          g_session.properties, EVENT_TRACE_CONTROL_STOP);
        if (stop_status == ERROR_SUCCESS || stop_status == ERROR_WMI_INSTANCE_NOT_FOUND) {
            g_session.session_handle = 0;
            free(g_session.properties);
            g_session.properties = NULL;
            CloseHandle(g_session.consumer_ready_event);
            g_session.consumer_ready_event = NULL;
        } else {
            fprintf(stderr, "[ETW] cleanup after CreateThread failure failed: status=%lu; retaining session state\\n",
                    stop_status);
            CloseHandle(g_session.consumer_ready_event);
            g_session.consumer_ready_event = NULL;
        }
        return -3;
    }
    return 0;
}

int aegis_etw_start(const char* session_name, const uint8_t (*providers)[16], size_t provider_count) {
    AcquireSRWLockExclusive(&g_lifecycle_lock);
    int rc = aegis_etw_start_impl(session_name, providers, provider_count);
    ReleaseSRWLockExclusive(&g_lifecycle_lock);
    return rc;
}

static int aegis_etw_stop_impl(const char* session_name) {
    (void)session_name;
    InterlockedExchange(&g_session.running, 0);

    /* Finish an in-flight callback before allowing its Zig context to die. */
    AcquireSRWLockExclusive(&g_lock);
    g_session.callback = NULL;
    g_session.callback_ctx = NULL;
    ReleaseSRWLockExclusive(&g_lock);

    if (g_session.session_handle) {
        ULONG status = ControlTraceW(g_session.session_handle, g_session.session_name,
                                     g_session.properties, EVENT_TRACE_CONTROL_STOP);
        if (status != ERROR_SUCCESS && status != ERROR_WMI_INSTANCE_NOT_FOUND) {
            fprintf(stderr, "[ETW] ControlTrace stop failed: status=%lu; retaining session resources\\n", status);
            if (g_session.consumer_thread && g_session.consumer_ready_event) {
                DWORD ready_result = WaitForSingleObject(g_session.consumer_ready_event, INFINITE);
                if (ready_result != WAIT_OBJECT_0) {
                    DWORD error = (ready_result == WAIT_FAILED) ? GetLastError() : ERROR_INVALID_DATA;
                    fprintf(stderr, "[ETW] consumer readiness wait failed: result=%lu error=%lu\\n",
                            ready_result, error);
                    return -9;
                }
                LONG64 trace_value = InterlockedExchange64(&g_session.consumer_handle, 0);
                if (trace_value != 0) {
                    ULONG close_status = CloseTrace((PROCESSTRACE_HANDLE)trace_value);
                    if (close_status != ERROR_SUCCESS && close_status != ERROR_CTX_CLOSE_PENDING) {
                        fprintf(stderr, "[ETW] CloseTrace after stop failure failed: status=%lu\\n", close_status);
                        return -9;
                    }
                }
                DWORD wait_result = WaitForSingleObject(g_session.consumer_thread, INFINITE);
                if (wait_result != WAIT_OBJECT_0) {
                    DWORD error = (wait_result == WAIT_FAILED) ? GetLastError() : ERROR_INVALID_DATA;
                    fprintf(stderr, "[ETW] consumer join after stop failure failed: result=%lu error=%lu\\n",
                            wait_result, error);
                    return -9;
                }
                CloseHandle(g_session.consumer_thread);
                g_session.consumer_thread = NULL;
            }
            return -8;
        }
        g_session.session_handle = 0;
    }
    if (g_session.consumer_thread) {
        /* A successful stop of a real-time session releases ProcessTrace.
         * Do not release session state unless the worker is actually joined. */
        DWORD wait_result = WaitForSingleObject(g_session.consumer_thread, INFINITE);
        if (wait_result != WAIT_OBJECT_0) {
            DWORD error = (wait_result == WAIT_FAILED) ? GetLastError() : ERROR_INVALID_DATA;
            fprintf(stderr, "[ETW] consumer join failed: result=%lu error=%lu; retaining resources\\n",
                    wait_result, error);
            return -9;
        }
        CloseHandle(g_session.consumer_thread);
        g_session.consumer_thread = NULL;
    }
    if (g_session.consumer_ready_event) {
        CloseHandle(g_session.consumer_ready_event);
        g_session.consumer_ready_event = NULL;
    }
    if (g_session.properties) {
        free(g_session.properties);
        g_session.properties = NULL;
    }
    return 0;
}

int aegis_etw_stop(const char* session_name) {
    AcquireSRWLockExclusive(&g_lifecycle_lock);
    int rc = aegis_etw_stop_impl(session_name);
    ReleaseSRWLockExclusive(&g_lifecycle_lock);
    return rc;
}

int aegis_etw_set_callback(aegis_etw_cb_t cb, void* ctx) {
    AcquireSRWLockExclusive(&g_lifecycle_lock);
    AcquireSRWLockExclusive(&g_lock);
    g_session.callback = cb;
    g_session.callback_ctx = ctx;
    ReleaseSRWLockExclusive(&g_lock);
    ReleaseSRWLockExclusive(&g_lifecycle_lock);
    return 0;
}
