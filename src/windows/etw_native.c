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
    TRACEHANDLE consumer_handle;
    EVENT_TRACE_PROPERTIES* properties;
    wchar_t session_name[64];
    aegis_etw_cb_t callback;
    void* callback_ctx;
    volatile LONG running;
    HANDLE consumer_thread;
    uint8_t ext_buffer[AEGIS_ETW_BUFFER_SIZE];
} aegis_etw_session_t;

static aegis_etw_session_t g_session;
static CRITICAL_SECTION g_lock;

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

    if (g_session.callback) {
        EnterCriticalSection(&g_lock);
        g_session.callback(g_session.callback_ctx, &out, g_session.ext_buffer, ext_len);
        LeaveCriticalSection(&g_lock);
    }
}

static DWORD WINAPI consumer_thread(LPVOID arg) {
    (void)arg;
    PROCESSTRACE_HANDLE trace = OpenTraceW(&((EVENT_TRACE_LOGFILEW){
        .LoggerName = g_session.session_name,
        .ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD,
        .EventRecordCallback = event_record_callback,
    }));
    if (trace == INVALID_PROCESSTRACE_HANDLE) return 1;
    ProcessTrace(&trace, 1, NULL, NULL);
    CloseTrace(trace);
    return 0;
}

int aegis_etw_start(const char* session_name, const uint8_t (*providers)[16], size_t provider_count) {
    if (g_session.session_handle != 0) {
        fprintf(stderr, "[ETW] start rejected: session already active\\n");
        return -1;
    }
    InitializeCriticalSection(&g_lock);
    MultiByteToWideChar(CP_UTF8, 0, session_name, -1, g_session.session_name, 64);

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
        ControlTraceW(g_session.session_handle, g_session.session_name,
                      g_session.properties, EVENT_TRACE_CONTROL_STOP);
        g_session.session_handle = 0;
        free(g_session.properties);
        g_session.properties = NULL;
        return -4;
    }

    InterlockedExchange(&g_session.running, 1);
    g_session.consumer_thread = CreateThread(NULL, 0, consumer_thread, NULL, 0, NULL);
    if (!g_session.consumer_thread) {
        fprintf(stderr, "[ETW] CreateThread failed: error=%lu\\n", GetLastError());
        StopTrace(g_session.session_handle, g_session.session_name, g_session.properties);
        free(g_session.properties);
        return -3;
    }
    return 0;
}

int aegis_etw_stop(const char* session_name) {
    (void)session_name;
    if (g_session.session_handle == 0) return -1;
    InterlockedExchange(&g_session.running, 0);
    if (g_session.session_handle) {
        StopTrace(g_session.session_handle, g_session.session_name, g_session.properties);
        g_session.session_handle = 0;
    }
    if (g_session.consumer_thread) {
        WaitForSingleObject(g_session.consumer_thread, 5000);
        CloseHandle(g_session.consumer_thread);
        g_session.consumer_thread = NULL;
    }
    if (g_session.properties) {
        free(g_session.properties);
        g_session.properties = NULL;
    }
    return 0;
}

int aegis_etw_set_callback(aegis_etw_cb_t cb, void* ctx) {
    EnterCriticalSection(&g_lock);
    g_session.callback = cb;
    g_session.callback_ctx = ctx;
    LeaveCriticalSection(&g_lock);
    return 0;
}
