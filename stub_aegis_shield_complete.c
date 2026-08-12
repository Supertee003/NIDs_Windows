
/*
 * AEGIS NIDS - Stub DLL: aegis_shield
 * Complete stub with ALL exports from .def file.
 * Replace with real Rust implementations.
 */

#include <stdint.h>

/* aegis_shield_submit_packet */
__declspec(dllexport) int32_t aegis_shield_submit_packet(
    const void* meta, const void* payload, uint32_t payload_len,
    const uint32_t* pattern_ids, uint32_t pattern_count) {
    return -1; /* stub: not submitted */
}

/* aegis_semi_nids_init */
__declspec(dllexport) int32_t aegis_semi_nids_init(void) {
    return 0; /* stub: success (was -1, changed to allow init) */
}

/* aegis_semi_nids_evaluate */
__declspec(dllexport) uint8_t aegis_semi_nids_evaluate(
    uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port,
    uint8_t ip_proto, double threat_score, uint8_t severity,
    uint32_t pattern_count, uint32_t alert_count) {
    return 0; /* stub: no action */
}

/* aegis_semi_nids_set_policy */
__declspec(dllexport) int32_t aegis_semi_nids_set_policy(uint32_t policy_id) {
    return -1;
}

/* aegis_semi_nids_get_pending_count */
__declspec(dllexport) uint32_t aegis_semi_nids_get_pending_count(void) {
    return 0;
}

/* aegis_semi_nids_fail_open_status */
__declspec(dllexport) uint8_t aegis_semi_nids_fail_open_status(void) {
    return 1; /* stub: fail-open is active */
}

/* aegis_semi_nids_update_load */
__declspec(dllexport) int32_t aegis_semi_nids_update_load(double cpu_load, double mem_load) {
    return -1;
}

/* aegis_semi_nids_block_ip */
__declspec(dllexport) int32_t aegis_semi_nids_block_ip(uint32_t ip, uint32_t reason) {
    return -1;
}

/* aegis_semi_nids_unblock_ip */
__declspec(dllexport) int32_t aegis_semi_nids_unblock_ip(uint32_t ip) {
    return -1;
}

/* aegis_semi_nids_get_stats */
__declspec(dllexport) int32_t aegis_semi_nids_get_stats(
    uint64_t* total, uint64_t* blocked, uint64_t* alerts,
    uint64_t* pending, uint64_t* fail_open) {
    if (total) *total = 0;
    if (blocked) *blocked = 0;
    if (alerts) *alerts = 0;
    if (pending) *pending = 0;
    if (fail_open) *fail_open = 0;
    return 0;
}

/* aegis_semi_nids_maintenance */
__declspec(dllexport) uint32_t aegis_semi_nids_maintenance(void) {
    return 0;
}

/* aegis_semi_nids_shutdown */
__declspec(dllexport) void aegis_semi_nids_shutdown(void) {
}

/* aegis_correlation_init */
__declspec(dllexport) int32_t aegis_correlation_init(void) {
    return 0; /* stub: success (was -1, changed to allow init) */
}
