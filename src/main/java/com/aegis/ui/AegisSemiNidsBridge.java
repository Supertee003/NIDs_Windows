package com.aegis.ui;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.LongByReference;
import com.sun.jna.ptr.DoubleByReference;

/**
 * AegisSemiNidsBridge — JNA bridge to Rust Semi-NIDS engine (aegis_shield.dll/.so)
 *
 * Implements all 3 Semi-NIDS properties via FFI:
 *   Property 1: Adaptive & Threshold-based Dropping
 *   Property 2: Graceful Degradation (Fail-Open)
 *   Property 3: Interactive Control Loop (Human-in-the-loop)
 */
public class AegisSemiNidsBridge {

    /** JNA interface to the Rust cdylib */
    public interface SemiNidsLib extends Library {
        // Init/Shutdown
        int aegis_semi_nids_init();
        void aegis_semi_nids_shutdown();

        // Property 1: Evaluate threat → decision
        // Must match Rust FFI: (src_ip, dst_ip, src_port, dst_port, ip_proto, threat_score, confidence, risk_flags, process_id)
        byte aegis_semi_nids_evaluate(
            int src_ip, int dst_ip,
            short src_port, short dst_port, short ip_proto,
            double threat_score, byte confidence,
            int risk_flags, int process_id
        );

        // Property 3: Human policy decisions
        int aegis_semi_nids_set_policy(long alert_id, byte decision);
        int aegis_semi_nids_get_pending_count();

        int aegis_semi_nids_get_pending(
            int index,
            LongByReference out_alert_id,
            IntByReference out_src_ip,
            DoubleByReference out_threat_score,
            byte[] out_confidence,
            byte[] out_decision
        );

        // Property 2: Fail-Open status
        byte aegis_semi_nids_fail_open_status();

        // Load update from Go perf monitor
        void aegis_semi_nids_update_load(byte cpu_pct, byte queue_pct, long pps);

        // Direct IP block/unblock
        int aegis_semi_nids_block_ip(int ip);
        int aegis_semi_nids_unblock_ip(int ip);

        // Maintenance
        int aegis_semi_nids_maintenance();
    }

    // ── Decision constants (match Rust SemiNidsDecision) ──
    public static final byte DECISION_PASS             = 0;
    public static final byte DECISION_ALERT_ONLY       = 1;
    public static final byte DECISION_RATE_LIMIT       = 2;
    public static final byte DECISION_BLOCK            = 3;
    public static final byte DECISION_BLOCK_PRESERVE   = 4;
    public static final byte DECISION_PENDING_HUMAN    = 5;

    // ── Human decision constants (match Rust HumanDecision) ──
    public static final byte HUMAN_BLOCK      = 1;
    public static final byte HUMAN_BLOCK_TEMP = 2;
    public static final byte HUMAN_WHITELIST  = 3;
    public static final byte HUMAN_IGNORE     = 4;
    public static final byte HUMAN_ESCALATE   = 5;

    // ── Load state constants (match Rust LoadState) ──
    public static final byte LOAD_NORMAL     = 0;
    public static final byte LOAD_ELEVATED   = 1;
    public static final byte LOAD_OVERLOADED = 2;
    public static final byte LOAD_CRITICAL   = 3;

    // ── Singleton ──
    private static SemiNidsLib lib = null;
    private static boolean loaded = false;

    public static synchronized boolean load() {
        if (loaded) return lib != null;
        try {
            lib = Native.load("aegis_shield", SemiNidsLib.class);
            loaded = true;
            return true;
        } catch (UnsatisfiedLinkError e) {
            loaded = true; // Don't retry
            return false;
        }
    }

    public static boolean isLoaded() {
        return lib != null;
    }

    // ── Convenience Methods ──

    public static int init() {
        if (!load()) return -1;
        return lib.aegis_semi_nids_init();
    }

    public static byte evaluate(int srcIp, int dstIp, int srcPort, int dstPort, int ipProto,
                                double threatScore, byte confidence, int riskFlags, int processId) {
        if (lib == null) return DECISION_PASS;
        return lib.aegis_semi_nids_evaluate(srcIp, dstIp,
                                            (short)srcPort, (short)dstPort, (short)ipProto,
                                            threatScore, confidence, riskFlags, processId);
    }

    /** Human decides on a pending alert */
    public static int setPolicy(long alertId, byte decision) {
        if (lib == null) return -1;
        return lib.aegis_semi_nids_set_policy(alertId, decision);
    }

    /** Get number of pending alerts (for UI badge) */
    public static int getPendingCount() {
        if (lib == null) return 0;
        return lib.aegis_semi_nids_get_pending_count();
    }

    /** Get fail-open status: 0=Normal, 1=Elevated, 2=Overloaded, 3=Critical */
    public static byte getFailOpenStatus() {
        if (lib == null) return LOAD_NORMAL;
        return lib.aegis_semi_nids_fail_open_status();
    }

    /** Update load from Go perf monitor */
    public static void updateLoad(byte cpuPct, byte queuePct, long pps) {
        if (lib == null) return;
        lib.aegis_semi_nids_update_load(cpuPct, queuePct, pps);
    }

    /** Block an IP immediately (from [Block IP] button) */
    public static int blockIp(int ip) {
        if (lib == null) return -1;
        return lib.aegis_semi_nids_block_ip(ip);
    }

    /** Unblock/whitelist an IP (from [Whitelist] button) */
    public static int unblockIp(int ip) {
        if (lib == null) return -1;
        return lib.aegis_semi_nids_unblock_ip(ip);
    }

    /** Periodic maintenance (expire temp blocks) */
    public static int maintenance() {
        if (lib == null) return 0;
        return lib.aegis_semi_nids_maintenance();
    }

    public static void shutdown() {
        if (lib != null) lib.aegis_semi_nids_shutdown();
    }

    // ── IP Utility ──
    public static String ipToString(int ip) {
        return String.format("%d.%d.%d.%d",
            (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
            (ip >> 8) & 0xFF, ip & 0xFF);
    }

    public static int ipToInt(String ip) {
        String[] parts = ip.split("\\.");
        if (parts.length != 4) return 0;
        return (Integer.parseInt(parts[0]) << 24) |
               (Integer.parseInt(parts[1]) << 16) |
               (Integer.parseInt(parts[2]) << 8) |
                Integer.parseInt(parts[3]);
    }

    // ── Decision Names ──
    public static String decisionName(byte decision) {
        switch (decision) {
            case 0: return "Pass";
            case 1: return "Alert Only";
            case 2: return "Rate Limit";
            case 3: return "Block";
            case 4: return "Block+Preserve";
            case 5: return "Pending Human";
            default: return "Unknown(" + decision + ")";
        }
    }

    public static String loadStateName(byte state) {
        switch (state) {
            case 0: return "Normal";
            case 1: return "Elevated";
            case 2: return "Overloaded (Fail-Open)";
            case 3: return "Critical (Fail-Open)";
            default: return "Unknown";
        }
    }

    // ── Instance convenience methods (for Vaadin UI event handlers) ──

    /** Block IP by string — converts to int and calls static method */
    public int blockIp(String ipStr) {
        int ip = ipToInt(ipStr);
        if (ip == 0) return -1;
        return blockIp(ip);
    }

    /** Unblock/whitelist IP by string */
    public int unblockIp(String ipStr) {
        int ip = ipToInt(ipStr);
        if (ip == 0) return -1;
        return unblockIp(ip);
    }
}
