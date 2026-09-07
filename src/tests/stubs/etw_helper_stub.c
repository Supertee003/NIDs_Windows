/* Test-only stub for aegis_etw_helper.dll.
 * Real implementation lives in src/windows/etw_native.c (built via CMake).
 * These stubs exist so `zig build test` can link without the native helper. */

#include <stddef.h>
#include <stdint.h>

__declspec(dllexport) int aegis_etw_start(const char *session_name, const uint8_t (*providers)[16], size_t provider_count)
{
    (void)session_name;
    (void)providers;
    (void)provider_count;
    return -1;
}

__declspec(dllexport) int aegis_etw_stop(const char *session_name)
{
    (void)session_name;
    return -1;
}

typedef void (*etw_callback_fn)(void *ctx, const void *rec, const uint8_t *ext_data, size_t ext_len);

__declspec(dllexport) int aegis_etw_set_callback(etw_callback_fn cb, void *ctx)
{
    (void)cb;
    (void)ctx;
    return -1;
}