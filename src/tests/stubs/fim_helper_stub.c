/* Test-only stub for aegis_fim_helper.dll.
 * Real implementation lives in src/windows/fim_native.c (built via CMake).
 * These stubs exist so `zig build test` can link without the native helper. */

#include <stddef.h>
#include <stdint.h>

__declspec(dllexport) void *aegis_fim_start(const char *path, uint32_t recursive, uint32_t filter)
{
    (void)path;
    (void)recursive;
    (void)filter;
    return NULL;
}

__declspec(dllexport) int aegis_fim_stop(void *handle)
{
    (void)handle;
    return -1;
}

__declspec(dllexport) int aegis_fim_poll(void *handle, uint8_t *out_buf, size_t out_len)
{
    (void)handle;
    (void)out_buf;
    (void)out_len;
    return -1;
}