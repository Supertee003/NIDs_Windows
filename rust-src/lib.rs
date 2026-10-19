// II15 + I18 - AEGIS PEP (Policy Enforcement Point) + Federation TLS (Rust)
//
// This crate exposes:
//   - aegis_pep_init / aegis_pep_enforce / aegis_pep_quota_remaining (PEP FFI)
//   - Federation TLS transport (Rustls-based mTLS server+client)
//
// Compiled as `aegis_pep.dll` (cdylib) and `aegis_pep.rlib` (for tests).
//
// PATCH-26: Policy Signing Verification Framework
//   Policy IR is signed with Ed25519 before loading.
//   Verification: Policy IR -> SHA-256 -> Ed25519 Verify -> Trust Store

#![deny(unsafe_op_in_unsafe_fn)]
#![allow(clippy::missing_safety_doc)]

use parking_lot::Mutex;
use std::collections::HashMap;
use std::ffi::c_int;
use std::sync::OnceLock;

// PATCH-26: Policy signing verification (production: use ring Ed25519)
pub fn verify_policy_signature(
    policy_data: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> bool {
    // Production: Ed25519 verify using ring crate
    if public_key.len() != 32 || signature.len() != 64 {
        return false;
    }
    // Verify signature is not all zeros (rejection of dummy signatures)
    if signature.iter().all(|&b| b == 0) {
        return false;
    }
    // Verify public key is not all zeros
    if public_key.iter().all(|&b| b == 0) {
        return false;
    }
    // Real Ed25519 verification using ring crate
    use ring::signature;
    let public_key_bytes: [u8; 32] = match public_key.try_into() {
        Ok(k) => k,
        Err(_) => return false,
    };
    let signature_bytes: [u8; 64] = match signature.try_into() {
        Ok(s) => s,
        Err(_) => return false,
    };
    let pubkey = signature::UnparsedPublicKey::new(
        &signature::ED25519,
        &public_key_bytes[..],
    );
    pubkey.verify(policy_data, &signature_bytes).is_ok()
}

// ============================================================================
// POL-SIGN-078: policy-verify FFI (transport of trust verdict only).
//
// Thin C ABI over verify_policy_signature for the Zig loader to call:
// 0 = valid signature, -1 = null pointer, -2 = verification failure
// (bad lengths, zero material, or crypto reject). No state, no policy
// mutation, no enforcement path — the caller decides what a valid or
// invalid verdict means. Wired: src/policy/policy_signing.zig
// (`verifyViaRust` -> sidecar envelope v1, verifyIrSidecar /
// verifyIrWithAnchors). Key custody (key generation/pinning/rotation)
// remains per ADR-0005 Q3; unsigned deployments stay untrusted until
// then.
// ============================================================================

/// Verify an Ed25519 signature over policy bytes.
/// Returns 0 when valid; -1 on null pointers; -2 on any failure.
#[no_mangle]
pub extern "C" fn aegis_policy_verify(
    policy_data: *const u8,
    policy_len: usize,
    signature: *const u8,
    signature_len: usize,
    public_key: *const u8,
    public_key_len: usize,
) -> c_int {
    if policy_data.is_null() || signature.is_null() || public_key.is_null() {
        return -1;
    }
    // Empty policy bytes verify nothing; fail closed before touching crypto.
    if policy_len == 0 {
        return -2;
    }
    let (data, sig, key) = unsafe {
        (
            std::slice::from_raw_parts(policy_data, policy_len),
            std::slice::from_raw_parts(signature, signature_len),
            std::slice::from_raw_parts(public_key, public_key_len),
        )
    };
    if verify_policy_signature(data, sig, key) {
        0
    } else {
        -2
    }
}

pub fn sha256_hash(data: &[u8]) -> [u8; 32] {
    // Pure Rust SHA-256 implementation
    let mut state: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    // Pre-processing: adding padding bits
    let msg_len = data.len();
    let bit_len = (msg_len as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    // Process each 512-bit block
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    let mut result = [0u8; 32];
    for i in 0..8 {
        result[i * 4..(i + 1) * 4].copy_from_slice(&state[i].to_be_bytes());
    }
    result
}

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

// ============================================================================
// 1. PEP FFI types â€” match the Zig-side definitions
// ============================================================================

#[repr(C)]
pub struct PepContext {
    pub caller_pid: u32,
    pub caller_capability_mask: u32,
    pub request_id: u64,
    pub policy_version: u32,
}

#[repr(C)]
pub struct PepRequest {
    pub decision_kind: u8,
    pub requested_action: u8,
    pub flow_id: u64,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub policy_id: u32,
    pub severity: u8,
    pub ctx: PepContext,
}

#[repr(C)]
pub struct PepResponse {
    pub decision: u8,
    pub reason: u32,
    pub quota_remaining: u32,
    pub signed_by: u32,
    pub filter_id: u64,
}

#[repr(C, packed)]
pub struct PepFilterState {
    pub filter_id: u64,
    pub remote_ipv4: u32,
    pub remote_port: u16,
    pub protocol: u8,
    pub present: u8,
    pub provider_status: u32,
}

// Decision enum (must match Zig side)
const DECISION_ALLOW: u8 = 0;
const DECISION_BLOCK: u8 = 1;
const DECISION_RATE_LIMIT: u8 = 2;
#[allow(dead_code)]
const DECISION_QUARANTINE: u8 = 3;
const DECISION_ESCALATE: u8 = 4;
#[allow(dead_code)]
const DECISION_DROP: u8 = 5;

// Policy-action ordinals from src/policy/policy_ir.zig.
const ACTION_PASS: u8 = 0;
const ACTION_LOG: u8 = 1;
const ACTION_ALERT: u8 = 2;
const ACTION_RATE_LIMIT: u8 = 3;
const ACTION_BLOCK: u8 = 4;
const ACTION_QUARANTINE: u8 = 5;
const ACTION_ESCALATE: u8 = 6;

#[cfg(test)]
mod action_contract_tests {
    use super::{ACTION_BLOCK, DECISION_BLOCK};

    #[test]
    fn request_and_response_block_ordinals_are_distinct_and_frozen() {
        assert_eq!(ACTION_BLOCK, 4);
        assert_eq!(DECISION_BLOCK, 1);
    }
}

#[cfg(windows)]
mod wfp_adapter {
    use std::ffi::{c_void, OsStr};
    use std::mem::transmute;
    use std::os::windows::ffi::OsStrExt;

    #[repr(C, packed)]
    pub struct FlowRequest {
        pub remote_ipv4: u32,
        pub remote_port: u16,
        pub protocol: u8,
        pub reserved: u8,
    }

    #[repr(C, packed)]
    pub struct FlowResponse {
        pub filter_id: u64,
        pub provider_status: u32,
    }

    #[repr(C, packed)]
    pub struct FilterState {
        pub filter_id: u64,
        pub remote_ipv4: u32,
        pub remote_port: u16,
        pub protocol: u8,
        pub present: u8,
        pub provider_status: u32,
    }

    type WfpBlockFlow = unsafe extern "system" fn(*const FlowRequest, *mut FlowResponse) -> i32;
    type WfpUnblockFilter = unsafe extern "system" fn(u64) -> i32;
    type WfpQueryFilter = unsafe extern "system" fn(u64, *mut FilterState) -> i32;
    type WfpOpen = unsafe extern "system" fn() -> i32;
    type WfpClose = unsafe extern "system" fn() -> i32;
    type WfpReadEvents = unsafe extern "system" fn(*mut u8, u32, *mut u32) -> i32;

    pub struct Adapter {
        module: *mut c_void,
        open: WfpOpen,
        /// EVT-212: optional device-release export, called on drop BEFORE
        /// FreeLibrary. The bridge DLL keeps the exclusive handle in a
        /// static; without the close, module unload orphans that open
        /// FILE_OBJECT (share 0) and starves every later CreateFileW in
        /// this process -- the exact starvation this daemon hit at boot.
        /// Optional like read_events: a provider copy that predates the
        /// export must still attest for enforcement; only handle hygiene
        /// is lost.
        close: Option<WfpClose>,
        block_flow: WfpBlockFlow,
        unblock_filter: WfpUnblockFilter,
        query_filter: WfpQueryFilter,
        /// EVT-211: optional read-only telemetry export. Optional on
        /// purpose: a provider copy that predates the read surface must
        /// still attest for enforcement; its reads surface as unavailable.
        read_events: Option<WfpReadEvents>,
    }

    unsafe extern "system" {
        fn LoadLibraryW(name: *const u16) -> *mut c_void;
        fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
        fn FreeLibrary(module: *mut c_void) -> i32;
    }

    impl Adapter {
        pub fn load() -> Option<Self> {
            // EVT-184: fall through candidates on INCOMPLETE loads, not just
            // missing files. A stale shadow copy (e.g. repo root, first on the
            // search order via CWD) that loads but lacks one export must not
            // poison the whole load -- it once failed T11 for weeks while
            // every direct probe passed. Each rejected module is freed.
            for candidate in [
                "aegis_wfp_user.dll",
                "build\\Release\\aegis_wfp_user.dll",
            ] {
                let name: Vec<u16> = OsStr::new(candidate)
                    .encode_wide()
                    .chain(Some(0))
                    .collect();
                let module = unsafe { LoadLibraryW(name.as_ptr()) };
                if module.is_null() {
                    continue;
                }
                let block_flow_name = b"aegis_wfp_ioctl_block_flow\0";
                let unblock_filter_name = b"aegis_wfp_ioctl_unblock_filter\0";
            let query_filter_name = b"aegis_wfp_ioctl_query_filter\0";
            let open_name = b"aegis_wfp_ioctl_open\0";
            let close_name = b"aegis_wfp_ioctl_close\0";
            let read_events_name = b"aegis_wfp_ioctl_read_events\0";
            let open = unsafe { GetProcAddress(module, open_name.as_ptr()) };
            let close = unsafe { GetProcAddress(module, close_name.as_ptr()) };
            let block_flow = unsafe { GetProcAddress(module, block_flow_name.as_ptr()) };
            let unblock_filter = unsafe { GetProcAddress(module, unblock_filter_name.as_ptr()) };
            let query_filter = unsafe { GetProcAddress(module, query_filter_name.as_ptr()) };
            let read_events = unsafe { GetProcAddress(module, read_events_name.as_ptr()) };
            if open.is_null() || block_flow.is_null() || unblock_filter.is_null() || query_filter.is_null() {
                unsafe { FreeLibrary(module) };
                continue; // incomplete shadow copy: try the next candidate
            }
            // EVT-211: telemetry is additive, so this export is NOT part of
            // the required-enforcement set (unlike the four above). An old
            // copy without it still enforces; its reads are labeled absent.
            let read_events = if read_events.is_null() {
                None
            } else {
                Some(unsafe { transmute::<*mut c_void, WfpReadEvents>(read_events) })
            };
            // EVT-212: device release is hygiene, not capability -- the same
            // optionality contract as read_events. Without it the drop below
            // leaks the exclusive handle (see Drop).
            let close = if close.is_null() {
                None
            } else {
                Some(unsafe { transmute::<*mut c_void, WfpClose>(close) })
            };

            // EVT-212: probe open BEFORE assembling the owner struct. The
            // old order built `Self` first and dropped it on the failure
            // path, so a rejected module was released twice (explicit
            // FreeLibrary + Drop) -- and once Drop also closed the handle
            // that became a call into an unmapped module. An adapter value
            // must only ever exist for a module whose open SUCCEEDED.
            let open_fn: WfpOpen = unsafe { transmute(open) };
            if unsafe { open_fn() } != 0 {
                unsafe { FreeLibrary(module) };
                continue; // device closed for this copy: try the next one
            }
            return Some(Self {
                module,
                open: open_fn,
                close,
                block_flow: unsafe { transmute(block_flow) },
                unblock_filter: unsafe { transmute(unblock_filter) },
                query_filter: unsafe { transmute(query_filter) },
                read_events,
            });
        }
        None
    }

        pub fn block_flow(&self, request: &FlowRequest) -> Option<u64> {
            let mut response = FlowResponse { filter_id: 0, provider_status: 0 };
            let rc = unsafe { (self.block_flow)(request, &mut response) };
            if rc == 0 && response.filter_id != 0 {
                Some(response.filter_id)
            } else {
                None
            }
        }

        pub fn unblock_filter(&self, filter_id: u64) -> bool {
            unsafe { (self.unblock_filter)(filter_id) == 0 }
        }

        pub fn query_filter(&self, filter_id: u64) -> Option<FilterState> {
            if filter_id == 0 { return None; }
            let mut state = FilterState {
                filter_id: 0, remote_ipv4: 0, remote_port: 0,
                protocol: 0, present: 0, provider_status: 0,
            };
            let rc = unsafe { (self.query_filter)(filter_id, &mut state) };
            if rc == 0 && state.filter_id == filter_id {
                Some(state)
            } else {
                None
            }
        }

        /// EVT-211: read-only ring telemetry through this adapter's open
        /// device handle. None when the provider copy predates the read
        /// export or the IOCTL fails (caller re-probes); Some(0) is a valid
        /// idle reading, never an error. Never blocks or mutates policy.
        pub fn read_events(&self, out: &mut [u8]) -> Option<u32> {
            let f = self.read_events?;
            let len = u32::try_from(out.len()).ok()?;
            if len == 0 {
                return None;
            }
            let mut n: u32 = 0;
            let rc = unsafe { f(out.as_mut_ptr(), len, &mut n) };
            if rc == 0 {
                Some(n)
            } else {
                None
            }
        }

    }

    impl Drop for Adapter {
        fn drop(&mut self) {
            // EVT-212: release the exclusive device handle BEFORE the module
            // goes away. g_wfp_device lives in a DLL static: FreeLibrary
            // alone leaves an orphaned open FILE_OBJECT (share 0) that fails
            // every later CreateFileW in this process, even through a fresh
            // module map. Boot attestation used to orphan it and the
            // daemon's kernel telemetry could then never open again.
            if let Some(close) = self.close {
                unsafe { close() };
            }
            unsafe { FreeLibrary(self.module) };
        }
    }
}

// ============================================================================
// 2. Quota manager â€” per-source-IP rate limiting
// ============================================================================

const QUOTA_WINDOW_MS: u64 = 1000;
const QUOTA_DEFAULT: u32 = 100; // blocks per second per source

struct QuotaEntry {
    count: u32,
    window_start_ms: u64,
}

struct PepState {
    quotas: HashMap<u32, QuotaEntry>,
    two_person_rule: bool,
    pending_approvals: HashMap<u64, u32>, // request_id â†’ approver_pid
}

static PEP: OnceLock<Mutex<PepState>> = OnceLock::new();

fn pep_state() -> &'static Mutex<PepState> {
    PEP.get_or_init(|| {
        Mutex::new(PepState {
            quotas: HashMap::new(),
            two_person_rule: false,
            pending_approvals: HashMap::new(),
        })
    })
}

// PEP-ADAPTER-CACHE-073: cached WFP bridge handle. Loading the user-mode
// DLL + opening the kernel device per BLOCK (LoadLibrary, 4x
// GetProcAddress, device open per call) storms handles at block rates and
// risks unload-during-callback hazards from the matching per-call
// FreeLibrary. The steady-state success path reuses one handle; any
// failure drops the entry so the next call re-probes (the old code
// retried every call — same self-healing, minus the storm).
#[cfg(windows)]
mod adapter_cache {
    use super::wfp_adapter::Adapter;
    use parking_lot::Mutex;
    use std::sync::OnceLock;

    static CACHED: OnceLock<Mutex<Option<Adapter>>> = OnceLock::new();

    fn slot() -> &'static Mutex<Option<Adapter>> {
        CACHED.get_or_init(|| Mutex::new(None))
    }

    // SAFETY: the module handle is exclusively owned here and every use
    // goes through the cache mutex, so no two threads enter the bridge
    // DLL concurrently through this path.
    unsafe impl Send for Adapter {}

    /// Run `f` against the cached bridge, loading on first use and on any
    /// prior failure. Returns None when no provider is available.
    pub fn with_adapter<T>(f: impl FnOnce(&Adapter) -> Option<T>) -> Option<T> {
        let mut guard = slot().lock();
        if guard.is_none() {
            *guard = Adapter::load();
        }
        match guard.as_mut() {
            Some(adapter) => {
                let out = f(adapter);
                if out.is_none() {
                    *guard = None;
                }
                out
            }
            None => None,
        }
    }
}

// ============================================================================
// 3. FFI surface
// ============================================================================

#[no_mangle]
pub extern "C" fn aegis_pep_init() -> c_int {
    // Initialize logging if needed
    let _ = pep_state();
    0
}

/// Attest the provider bridge without mutating host policy.
///
/// A provider is ready only when the user-mode bridge DLL is present, exports
/// the required IOCTL surface, and can open the kernel device. This does not
/// assert that a block has occurred; host-effect capability remains a separate
/// controlled-proof result.
///
/// EVT-212: attestation runs THROUGH the adapter cache, adopting the single
/// sole-owner handle. A private load-and-drop here orphaned that exclusive
/// handle whenever it succeeded, and failed with a sharing violation
/// whenever the cache already held the device -- either way the daemon's own
/// telemetry was starved while every fresh-process probe still read fine.
#[no_mangle]
pub extern "C" fn aegis_pep_provider_ready() -> c_int {
    #[cfg(windows)]
    {
        if adapter_cache::with_adapter(|_| Some(1u8)).is_some() {
            return 1;
        }
    }
    0
}

#[no_mangle]
pub extern "C" fn aegis_pep_shutdown() {
    // Flush any pending state (best-effort)
    if let Some(state) = PEP.get() {
        let mut s = state.lock();
        s.quotas.clear();
        s.pending_approvals.clear();
    }
}

/// Consume one BLOCK authorization from the per-source sliding window.
/// Returns (quota_remaining, allowed). Pure state logic, no I/O, so unit
/// tests can pin the window behavior without touching the WFP adapter.
fn quota_consume(state: &mut PepState, src_ip: u32, now_ms: u64) -> (u32, bool) {
    let entry = state.quotas.entry(src_ip).or_insert(QuotaEntry {
        count: 0,
        window_start_ms: now_ms,
    });
    if now_ms.saturating_sub(entry.window_start_ms) >= QUOTA_WINDOW_MS {
        entry.window_start_ms = now_ms;
        entry.count = 0;
    }
    if entry.count >= QUOTA_DEFAULT {
        return (0, false);
    }
    entry.count += 1;
    (QUOTA_DEFAULT - entry.count, true)
}

#[no_mangle]
pub unsafe extern "C" fn aegis_pep_enforce(
    req: *const PepRequest,
    resp: *mut PepResponse,
) -> c_int {
    if req.is_null() || resp.is_null() {
        return -1;
    }
    let req = unsafe { &*req };
    let resp = unsafe { &mut *resp };

    // Default is non-enforcing until authorization and adapter execution both
    // succeed. An unavailable/failed enforcement path must never look like an
    // authorized ALLOW to the caller.
    let mut decision = DECISION_ALLOW;
    let mut reason = 0u32;
    let mut quota_remaining = QUOTA_DEFAULT;
    let signed_by = 0u32;
    let mut filter_id = 0u64;

    let state = pep_state();
    let mut s = state.lock();

    // Advisory actions do not require a privileged capability. Every action
    // that can mutate or constrain traffic must be explicitly authorized.
    let requires_privilege = matches!(
        req.requested_action,
        ACTION_RATE_LIMIT | ACTION_BLOCK | ACTION_QUARANTINE | ACTION_ESCALATE
    );
    if requires_privilege && (req.ctx.caller_capability_mask & 0x01) == 0 {
        decision = DECISION_ESCALATE;
        reason = 1; // authorization denied: insufficient capability
    } else if matches!(req.requested_action, ACTION_PASS | ACTION_LOG | ACTION_ALERT) {
        // Non-enforcing policy actions remain non-privileged.
        decision = DECISION_ALLOW;
    } else if req.requested_action == ACTION_ESCALATE {
        decision = DECISION_ESCALATE;
        reason = 2; // explicit policy escalation
    } else if req.requested_action == ACTION_RATE_LIMIT {
        decision = DECISION_RATE_LIMIT;
        reason = 3; // explicit policy rate limit
    } else if req.requested_action == ACTION_QUARANTINE {
        // QUAR-RCPT-112: quarantine constrains traffic like a block, so it
        // clears the same bars: the severity>=7 two-person approval gate
        // below, the shared quota window, and adapter execution that mints
        // a filter_id. The WFP primitive underneath is a flow block; the
        // quarantine semantics live in the returned decision/receipt, which
        // is what the Zig verifier keys on — never on filter provenance.
        if req.severity >= 7 && s.two_person_rule {
            // Need approval
            match s.pending_approvals.remove(&req.ctx.request_id) {
                Some(_) => {
                    decision = DECISION_QUARANTINE;
                }
                None => {
                    decision = DECISION_ESCALATE;
                    reason = 2; // needs approval
                }
            }
        } else {
            decision = DECISION_QUARANTINE;
            reason = 5; // quarantine requested; adapter execution below
        }
    } else if req.requested_action == ACTION_BLOCK {
        // High-severity block — check two-person rule if enabled.
        // Approvals are one-shot: a consumed approval cannot authorize a
        // second request, even for the same request_id replay.
        if req.severity >= 7 && s.two_person_rule {
            // Need approval
            match s.pending_approvals.remove(&req.ctx.request_id) {
                Some(_) => {
                    decision = DECISION_BLOCK;
                }
                None => {
                    decision = DECISION_ESCALATE;
                    reason = 2; // needs approval
                }
            }
        } else {
            decision = DECISION_BLOCK;
        }
    } else {
        // Unknown action values fail closed as an authorization denial.
        // The default `decision` is DECISION_ALLOW, so this branch must
        // overwrite it — setting only `reason` would return ALLOW for an
        // unclassifiable request, which is a fail-open on the sole
        // enforcement authority.
        decision = DECISION_ESCALATE;
        reason = 6;
    }
    if decision == DECISION_BLOCK || decision == DECISION_QUARANTINE {
        // T3-QUOTA: per-source sliding window over BLOCK and QUARANTINE
        // authorizations (shared window: a separate quarantine quota would
        // let quarantine requests bypass the block rate limit).
        // An exhausted quota fails closed to ESCALATE (reason 7), never to
        // ALLOW, and the window resets after QUOTA_WINDOW_MS.
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let (remaining, allowed) = quota_consume(&mut s, req.src_ip, now_ms);
        quota_remaining = remaining;
        if !allowed {
            decision = DECISION_ESCALATE;
            reason = 7; // quota exceeded
        }
    }
    drop(s);

    // QUAR-RCPT-112: quarantine executes through the same WFP flow-block
    // primitive (no separate quarantine filter class exists below the PEP);
    // the returned decision/receipt carries the quarantine semantics.
    if decision == DECISION_BLOCK || decision == DECISION_QUARANTINE {
        #[cfg(windows)]
        {
            // PEP-ADAPTER-CACHE-073: cached bridge (re-probes on failure).
            let flow = wfp_adapter::FlowRequest {
                remote_ipv4: req.dst_ip,
                remote_port: req.dst_port,
                protocol: req.protocol,
                reserved: 0,
            };
            match adapter_cache::with_adapter(|adapter| adapter.block_flow(&flow)) {
                Some(id) => filter_id = id,
                None => {
                    decision = DECISION_ESCALATE;
                    reason = 4;
                }
            }
        }
        #[cfg(not(windows))]
        {
            decision = DECISION_ESCALATE;
            reason = 4;
        }
    }

    resp.decision = decision;
    resp.reason = reason;
    resp.quota_remaining = quota_remaining;
    resp.signed_by = signed_by;
    resp.filter_id = filter_id;
    0
}

/// Enable or disable the two-person rule for high-severity BLOCK requests.
/// Privileged-only (capability bit 0x01); disabling also drops every pending
/// approval so a stale approval can never authorize a later request.
#[no_mangle]
pub extern "C" fn aegis_pep_set_two_person_rule(enabled: u32, caller_capability_mask: u32) -> c_int {
    if (caller_capability_mask & 0x01) == 0 {
        return -3;
    }
    let state = pep_state();
    let mut s = state.lock();
    s.two_person_rule = enabled != 0;
    if !s.two_person_rule {
        s.pending_approvals.clear();
    }
    0
}

/// Record a second-human approval for one enforcement request. Approvals are
/// one-shot: a successful BLOCK consumes its approval. Privileged-only.
#[no_mangle]
pub extern "C" fn aegis_pep_approve(request_id: u64, approver_pid: u32, caller_capability_mask: u32) -> c_int {
    if request_id == 0 {
        return -3;
    }
    if (caller_capability_mask & 0x01) == 0 {
        return -3;
    }
    let state = pep_state();
    let mut s = state.lock();
    s.pending_approvals.insert(request_id, approver_pid);
    0
}

#[no_mangle]
pub extern "C" fn aegis_pep_unblock_ip(
    ipv4: u32,
    caller_pid: u32,
    caller_capability_mask: u32,
    request_id: u64,
) -> c_int {
    let _ = (ipv4, caller_pid, request_id);
    if (caller_capability_mask & 0x01) == 0 {
        return -3;
    }
    // IP-only cleanup is not receipt-aware and cannot prove exact ownership.
    // Preserve the symbol for ABI compatibility, but never mutate WFP through it.
    -4
}

/// Remove exactly the filter identified by a previously issued enforcement
/// receipt. The receipt's filter_id is the only accepted cleanup identity.
#[no_mangle]
pub extern "C" fn aegis_pep_unblock_filter(
    filter_id: u64,
    caller_pid: u32,
    caller_capability_mask: u32,
    request_id: u64,
) -> c_int {
    let _ = (caller_pid, request_id);
    if filter_id == 0 || (caller_capability_mask & 0x01) == 0 {
        return -3;
    }

    #[cfg(windows)]
    {
        if let Some(adapter) = wfp_adapter::Adapter::load() {
            if adapter.unblock_filter(filter_id) {
                return 0;
            }
        }
    }

    -2
}

/// Read-only exact-filter postcondition query. A zero/unknown filter_id is
/// never treated as present, and IP-only lookup is intentionally unsupported.
#[no_mangle]
pub extern "C" fn aegis_pep_query_filter(
    filter_id: u64,
    out: *mut PepFilterState,
) -> c_int {
    if filter_id == 0 || out.is_null() {
        return -3;
    }
    #[cfg(windows)]
    {
        if let Some(adapter) = wfp_adapter::Adapter::load() {
            if let Some(state) = adapter.query_filter(filter_id) {
                unsafe {
                    (*out).filter_id = state.filter_id;
                    (*out).remote_ipv4 = state.remote_ipv4;
                    (*out).remote_port = state.remote_port;
                    (*out).protocol = state.protocol;
                    (*out).present = state.present;
                    (*out).provider_status = state.provider_status;
                }
                return 0;
            }
        }
    }
    -2
}

/// EVT-211: read-only kernel flow telemetry (5-tuple ring records) through
/// the cached sole-owner adapter. FLOW visibility only -- the ring carries
/// no payload bytes (driver construction), it can never block or mutate
/// host policy, and it mints no receipt. Returns 0 with `bytes_read` set
/// (0 = idle ring, a valid non-error state), -1 when no provider copy
/// supports the read surface, -3 on invalid arguments. A -1 must be
/// labeled by callers, never rendered as a zero-row reading.
#[no_mangle]
pub extern "C" fn aegis_pep_read_events(
    out_buf: *mut u8,
    buf_size: u32,
    bytes_read: *mut u32,
) -> c_int {
    if out_buf.is_null() || bytes_read.is_null() || buf_size == 0 {
        return -3;
    }
    #[cfg(windows)]
    {
        let out = unsafe { std::slice::from_raw_parts_mut(out_buf, buf_size as usize) };
        if let Some(n) = adapter_cache::with_adapter(|a| a.read_events(out)) {
            unsafe {
                *bytes_read = n;
            }
            return 0;
        }
    }
    -1
}

#[no_mangle]
pub extern "C" fn aegis_pep_quota_remaining(src_ip: u32) -> u32 {
    let state = pep_state();
    let s = state.lock();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    if let Some(entry) = s.quotas.get(&src_ip) {
        if now_ms.saturating_sub(entry.window_start_ms) < QUOTA_WINDOW_MS {
            return QUOTA_DEFAULT.saturating_sub(entry.count);
        }
    }
    QUOTA_DEFAULT
}

// ============================================================================
// 4. Federation TLS (Rustls)
// ============================================================================

pub mod federation_tls {
    //! FED-P2A STATUS — REAL crypto, loopback-proven, still UNWIRED.
    //! Client + server configs are built from caller-supplied PEM roots
    //! and chain/key; empty or unparseable trust material fails closed at
    //! construction. mTLS is honored when `require_client_auth` is set.
    //! There is still NO FFI exposure and NO production caller: the Zig
    //! TLS stack stays the only Transport vtable until the P2B one-stack
    //! cutover (ADR-0007), and the daemon speaks standalone. Never mistake
    //! loopback-proven for production-wired.
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream, ToSocketAddrs};
    use std::sync::Arc;

    /// PEM-encoded bytes throughout: `cert_chain` (leaf first),
    /// `private_key` (PKCS#8 / RSA / SEC1 PEM), `trusted_roots`
    /// (concatenated PEM certificates). Empty roots fail closed.
    pub struct TlsConfig {
        pub cert_chain: Vec<Vec<u8>>,
        pub private_key: Vec<u8>,
        pub trusted_roots: Vec<Vec<u8>>,
        pub require_client_auth: bool,
        /// DNS name the client verifies (tests use "localhost").
        pub server_name: String,
    }

    impl Default for TlsConfig {
        fn default() -> Self {
            Self {
                cert_chain: Vec::new(),
                private_key: Vec::new(),
                trusted_roots: Vec::new(),
                require_client_auth: true,
                server_name: "localhost".to_string(),
            }
        }
    }

    fn roots_from_pem(pem: &[u8]) -> Result<rustls::RootCertStore, Box<dyn std::error::Error>> {
        let mut store = rustls::RootCertStore::empty();
        let mut reader = std::io::BufReader::new(pem);
        let certs: Vec<_> = rustls_pemfile::certs(&mut reader).collect::<Result<_, _>>()?;
        if certs.is_empty() {
            return Err("federation_tls: no trust anchors (empty roots fail closed)".into());
        }
        for cert in certs {
            store
                .add(cert)
                .map_err(|e| format!("federation_tls: bad trust anchor: {e}"))?;
        }
        Ok(store)
    }

    fn chain_from_pem(chain: &[Vec<u8>]) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, Box<dyn std::error::Error>> {
        let mut out = Vec::with_capacity(chain.len());
        for pem in chain {
            let mut reader = std::io::BufReader::new(pem.as_slice());
            let mut found = false;
            for cert in rustls_pemfile::certs(&mut reader) {
                out.push(cert?);
                found = true;
            }
            if !found {
                return Err("federation_tls: chain entry holds no certificate".into());
            }
        }
        Ok(out)
    }

    fn key_from_pem(pem: &[u8]) -> Result<rustls::pki_types::PrivateKeyDer<'static>, Box<dyn std::error::Error>> {
        let mut reader = std::io::BufReader::new(pem);
        // Accept PKCS#8, RSA, or SEC1 — whichever the operator provisions.
        if let Some(key) = rustls_pemfile::pkcs8_private_keys(&mut reader).next() {
            return Ok(rustls::pki_types::PrivateKeyDer::Pkcs8(key?));
        }
        let mut reader = std::io::BufReader::new(pem);
        if let Some(key) = rustls_pemfile::rsa_private_keys(&mut reader).next() {
            return Ok(rustls::pki_types::PrivateKeyDer::Pkcs1(key?));
        }
        let mut reader = std::io::BufReader::new(pem);
        if let Some(key) = rustls_pemfile::ec_private_keys(&mut reader).next() {
            return Ok(rustls::pki_types::PrivateKeyDer::Sec1(key?));
        }
        Err("federation_tls: private key missing or not PKCS#8/RSA/SEC1 PEM".into())
    }

    pub struct TlsTransport {
        config: Arc<rustls::ClientConfig>,
        server_config: Option<Arc<rustls::ServerConfig>>,
        server_name: String,
    }

    /// An established client session: encrypted stream over loopback-or-later TCP.
    pub struct TlsSession {
        stream: rustls::StreamOwned<rustls::ClientConnection, TcpStream>,
    }

    /// An accepted server session.
    pub struct TlsServerSession {
        stream: rustls::StreamOwned<rustls::ServerConnection, TcpStream>,
    }

    impl TlsSession {
        pub fn send(&mut self, payload: &[u8]) -> std::io::Result<()> {
            self.stream.write_all(payload)?;
            self.stream.flush()
        }
        pub fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.stream.read(buf)
        }
        pub fn peer_certificates(&self) -> Option<Vec<Vec<u8>>> {
            self.stream.conn.peer_certificates().map(|certs| {
                certs.iter().map(|c| c.as_ref().to_vec()).collect()
            })
        }
    }

    impl TlsServerSession {
        pub fn send(&mut self, payload: &[u8]) -> std::io::Result<()> {
            self.stream.write_all(payload)?;
            self.stream.flush()
        }
        pub fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.stream.read(buf)
        }
        pub fn peer_certificates(&self) -> Option<Vec<Vec<u8>>> {
            self.stream.conn.peer_certificates().map(|certs| {
                certs.iter().map(|c| c.as_ref().to_vec()).collect()
            })
        }
    }

    impl TlsTransport {
        pub fn new(cfg: TlsConfig) -> Result<Self, Box<dyn std::error::Error>> {
            if cfg.server_name.is_empty() {
                return Err("federation_tls: empty server name fails closed".into());
            }
            let mut roots_pem = Vec::new();
            for root in &cfg.trusted_roots {
                roots_pem.extend_from_slice(root);
            }
            let roots = roots_from_pem(&roots_pem)?;

            let client_config = if cfg.cert_chain.is_empty() {
                rustls::ClientConfig::builder()
                    .with_root_certificates(roots.clone())
                    .with_no_client_auth()
            } else {
                let certs = chain_from_pem(&cfg.cert_chain)?;
                let key = key_from_pem(&cfg.private_key)?;
                rustls::ClientConfig::builder()
                    .with_root_certificates(roots.clone())
                    .with_client_auth_cert(certs, key)
                    .map_err(|e| format!("federation_tls: client auth cert: {e}"))?
            };
            let server_roots = Arc::new(roots);

            // Server identity is optional: a client-only node carries no
            // chain and must never accept. Requiring it here would force
            // every client to hold a server key.
            let server_config = if cfg.cert_chain.is_empty() {
                None
            } else {
                let certs = chain_from_pem(&cfg.cert_chain)?;
                let key = key_from_pem(&cfg.private_key)?;
                let built = if cfg.require_client_auth {
                    let verifier = rustls::server::WebPkiClientVerifier::builder(server_roots)
                        .build()
                        .map_err(|e| format!("federation_tls: client verifier: {e}"))?;
                    rustls::ServerConfig::builder()
                        .with_client_cert_verifier(verifier)
                        .with_single_cert(certs, key)
                        .map_err(|e| format!("federation_tls: server cert: {e}"))?
                } else {
                    rustls::ServerConfig::builder()
                        .with_no_client_auth()
                        .with_single_cert(certs, key)
                        .map_err(|e| format!("federation_tls: server cert: {e}"))?
                };
                Some(Arc::new(built))
            };

            Ok(Self {
                config: Arc::new(client_config),
                server_config,
                server_name: cfg.server_name,
            })
        }

        /// Open an encrypted session to `addr` (host:port), verifying the
        /// construction-time server name. Used by tests on 127.0.0.1;
        /// production use waits for the P2B FFI + wiring slice.
        pub fn connect<A: ToSocketAddrs>(
            &self,
            addr: A,
        ) -> Result<TlsSession, Box<dyn std::error::Error>> {
            let name = rustls::pki_types::ServerName::try_from(self.server_name.clone())
                .map_err(|e| format!("federation_tls: bad server name: {e}"))?;
            let conn = rustls::ClientConnection::new(self.config.clone(), name)
                .map_err(|e| format!("federation_tls: client handshake: {e}"))?;
            let sock = TcpStream::connect(addr).map_err(|e| format!("federation_tls: tcp: {e}"))?;
            Ok(TlsSession {
                stream: rustls::StreamOwned::new(conn, sock),
            })
        }

        /// Accept one encrypted session (server side). Fails when this
        /// transport holds no server identity (client-only node).
        pub fn accept(
            &self,
            listener: &TcpListener,
        ) -> Result<TlsServerSession, Box<dyn std::error::Error>> {
            // Fail fast: a client-only node must never block on accept.
            if !self.has_server_identity() {
                return Err(
                    "federation_tls: accept without server identity fails closed".into(),
                );
            }
            let (sock, _) = listener.accept().map_err(|e| format!("federation_tls: accept: {e}"))?;
            self.accept_socket(sock)
        }

        /// Complete the server side of a handshake on an already-accepted
        /// socket (used by the FFI listener, which owns the TcpListener).
        pub fn accept_socket(
            &self,
            sock: TcpStream,
        ) -> Result<TlsServerSession, Box<dyn std::error::Error>> {
            let server_config = self.server_config.as_ref().ok_or(
                "federation_tls: accept without server identity fails closed",
            )?;
            let conn = rustls::ServerConnection::new(server_config.clone())
                .map_err(|e| format!("federation_tls: server handshake: {e}"))?;
            Ok(TlsServerSession {
                stream: rustls::StreamOwned::new(conn, sock),
            })
        }

        /// Whether this transport can accept (false for client-only nodes
        /// built without a chain). Non-blocking by construction.
        pub fn has_server_identity(&self) -> bool {
            self.server_config.is_some()
        }
    }
}

// ============================================================================
// FED-P2B1: outbound client-session FFI (transport only, never enforcement).
//
// The P2 verdict (Rust-rustls via FFI) needs a narrow C ABI for the Zig
// Transport vtable to delegate through. This exposes outbound client
// sessions ONLY: connect / send / recv / close over an opaque u64
// handle. There is deliberately no listen/accept FFI (no production
// listener design yet — that is P4), no config mutation, and no path to
// enforcement: bytes in, bytes out, fail-closed codes on every misuse.
// The Zig mock stack stays until the P2B2 cutover; nothing calls this
// FFI yet.
// ============================================================================

struct FedSessionTable {
    next_id: u64,
    // Sessions live behind per-session locks: the table lock is held
    // only for lookup/insert/remove (never across I/O). Holding one
    // global lock across send/recv deadlocked full-duplex peers — each
    // side waited on the other's flight while holding the shared lock.
    sessions: HashMap<u64, std::sync::Arc<parking_lot::Mutex<FedSession>>>,
}

/// Client or server side of an encrypted session. Both directions use
/// the same send/recv verbs; the handshake role differs. One table,
/// one close path, no role confusion at the FFI boundary.
enum FedSession {
    Client(federation_tls::TlsSession),
    Server(federation_tls::TlsServerSession),
}

impl FedSession {
    fn send(&mut self, payload: &[u8]) -> std::io::Result<()> {
        match self {
            FedSession::Client(s) => s.send(payload),
            FedSession::Server(s) => s.send(payload),
        }
    }

    fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            FedSession::Client(s) => s.recv(buf),
            FedSession::Server(s) => s.recv(buf),
        }
    }
}

static FED_SESSIONS: OnceLock<Mutex<FedSessionTable>> = OnceLock::new();

fn fed_sessions() -> &'static Mutex<FedSessionTable> {
    FED_SESSIONS.get_or_init(|| {
        Mutex::new(FedSessionTable {
            next_id: 1,
            sessions: HashMap::new(),
        })
    })
}

fn fed_bytes(ptr: *const u8, len: usize) -> Option<Vec<u8>> {
    if ptr.is_null() {
        return if len == 0 { Some(Vec::new()) } else { None };
    }
    if len == 0 {
        return Some(Vec::new());
    }
    Some(unsafe { std::slice::from_raw_parts(ptr, len).to_vec() })
}

fn fed_str(ptr: *const std::ffi::c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    unsafe { std::ffi::CStr::from_ptr(ptr).to_str().ok().map(|s| s.to_string()) }
}

/// Open an encrypted client session. Returns 0 and writes the session
/// handle on success; -1 null/bad string, -2 TCP/TLS failure.
#[no_mangle]
pub extern "C" fn aegis_fed_connect(
    host: *const std::ffi::c_char,
    port: u16,
    roots_pem: *const u8,
    roots_len: usize,
    chain_pem: *const u8,
    chain_len: usize,
    key_pem: *const u8,
    key_len: usize,
    server_name: *const std::ffi::c_char,
    out_handle: *mut u64,
) -> c_int {
    if out_handle.is_null() {
        return -1;
    }
    let (Some(host), Some(server_name)) = (fed_str(host), fed_str(server_name)) else {
        return -1;
    };
    let (Some(roots), Some(chain), Some(key)) = (
        fed_bytes(roots_pem, roots_len),
        fed_bytes(chain_pem, chain_len),
        fed_bytes(key_pem, key_len),
    ) else {
        return -1;
    };
    let chain_vecs = if chain.is_empty() {
        Vec::new()
    } else {
        vec![chain]
    };
    let cfg = federation_tls::TlsConfig {
        cert_chain: chain_vecs,
        private_key: key,
        trusted_roots: vec![roots],
        require_client_auth: true,
        server_name,
    };
    let transport = match federation_tls::TlsTransport::new(cfg) {
        Ok(t) => t,
        Err(_) => return -2,
    };
    let session = match transport.connect((host.as_str(), port)) {
        Ok(s) => s,
        Err(_) => return -2,
    };
    let mut table = fed_sessions().lock();
    let id = table.next_id;
    table.next_id += 1;
    table.sessions.insert(id, std::sync::Arc::new(parking_lot::Mutex::new(FedSession::Client(session))));
    unsafe {
        *out_handle = id;
    }
    0
}

/// Send bytes on a session. 0 ok; -1 null; -2 IO/TLS failure; -3 unknown handle.
#[no_mangle]
pub extern "C" fn aegis_fed_send(
    handle: u64,
    data: *const u8,
    len: usize,
) -> c_int {
    if data.is_null() && len != 0 {
        return -1;
    }
    let bytes: &[u8] = if len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(data, len) }
    };
    // Clone the session Arc under the table lock, then release it BEFORE
    // doing I/O: holding the global lock across the network deadlocks
    // full-duplex peers (each side waits on the other's flight).
    let session = {
        let table = fed_sessions().lock();
        match table.sessions.get(&handle) {
            Some(s) => s.clone(),
            None => return -3,
        }
    };
    let rc = match session.lock().send(bytes) {
        Ok(()) => 0,
        Err(_) => -2,
    };
    rc
}

/// Receive up to `cap` bytes; writes the count to `out_n`. 0 ok (n may be
/// 0 on clean EOF); -1 null; -2 IO/TLS failure; -3 unknown handle.
#[no_mangle]
pub extern "C" fn aegis_fed_recv(
    handle: u64,
    buf: *mut u8,
    cap: usize,
    out_n: *mut usize,
) -> c_int {
    if buf.is_null() || out_n.is_null() {
        return -1;
    }
    let out: &mut [u8] = if cap == 0 {
        &mut []
    } else {
        unsafe { std::slice::from_raw_parts_mut(buf, cap) }
    };
    // Same lock discipline as send: clone under the table lock, I/O out.
    let session = {
        let table = fed_sessions().lock();
        match table.sessions.get(&handle) {
            Some(s) => s.clone(),
            None => return -3,
        }
    };
    let rc = match session.lock().recv(out) {
        Ok(n) => {
            unsafe {
                *out_n = n;
            }
            0
        }
        Err(_) => -2,
    };
    rc
}

/// Close a session. 0 ok; -3 unknown handle (double close fails closed).
#[no_mangle]
pub extern "C" fn aegis_fed_close(handle: u64) -> c_int {
    let mut table = fed_sessions().lock();
    if table.sessions.remove(&handle).is_some() {
        0
    } else {
        -3
    }
}

// ============================================================================
// FED-LSTN-085: loopback-only listener FFI (transport only, never
// enforcement). Completes the duplex capability: Rust already accepted
// internally (TlsTransport::accept, proven in P2A tests); this exposes
// listen + accept so a Zig peer can be served without any party
// touching plaintext. Exposure is contained BY CONSTRUCTION: the bind
// address is hardcoded to 127.0.0.1 (no wildcard option exists), mTLS
// honors require_client_auth from the same TlsConfig path, and nothing
// in the daemon calls this (no listener runs offensively). A future
// P4-listener slice decides daemon wiring; this slice proves the FFI.
// ============================================================================

struct FedListenerTable {
    next_id: u64,
    listeners: HashMap<u64, FedListener>,
}

struct FedListener {
    listener: std::net::TcpListener,
    transport: std::sync::Arc<federation_tls::TlsTransport>,
}

static FED_LISTENERS: OnceLock<Mutex<FedListenerTable>> = OnceLock::new();

fn fed_listeners() -> &'static Mutex<FedListenerTable> {
    FED_LISTENERS.get_or_init(|| {
        Mutex::new(FedListenerTable {
            next_id: 1,
            listeners: HashMap::new(),
        })
    })
}

/// Bind 127.0.0.1:port with mTLS server identity. Returns 0 and writes
/// the listener handle; -1 null/bad input, -2 TLS material or bind
/// failure. The port may be 0 (ephemeral); read back the bound address
/// with aegis_fed_listen_addr.
#[no_mangle]
pub extern "C" fn aegis_fed_listen(
    port: u16,
    roots_pem: *const u8,
    roots_len: usize,
    chain_pem: *const u8,
    chain_len: usize,
    key_pem: *const u8,
    key_len: usize,
    require_client_auth: c_int,
    out_listener: *mut u64,
) -> c_int {
    if out_listener.is_null() {
        return -1;
    }
    let (Some(roots), Some(chain), Some(key)) = (
        fed_bytes(roots_pem, roots_len),
        fed_bytes(chain_pem, chain_len),
        fed_bytes(key_pem, key_len),
    ) else {
        return -1;
    };
    if chain.is_empty() {
        return -2;
    }
    let cfg = federation_tls::TlsConfig {
        cert_chain: vec![chain],
        private_key: key,
        trusted_roots: vec![roots],
        require_client_auth: require_client_auth != 0,
        server_name: "localhost".to_string(),
    };
    let transport = match federation_tls::TlsTransport::new(cfg) {
        Ok(t) => t,
        Err(_) => return -2,
    };
    // Loopback ONLY: no parameter, no wildcard, no alternative.
    let listener = match std::net::TcpListener::bind(("127.0.0.1", port)) {
        Ok(l) => l,
        Err(_) => return -2,
    };
    let mut table = fed_listeners().lock();
    let id = table.next_id;
    table.next_id += 1;
    table.listeners.insert(id, FedListener {
        listener,
        transport: std::sync::Arc::new(transport),
    });
    unsafe {
        *out_listener = id;
    }
    0
}

/// Report the bound port of a listener (u16 host order). Returns 0 on
/// success; -1 null; -3 unknown listener.
#[no_mangle]
pub extern "C" fn aegis_fed_listen_port(listener: u64, out_port: *mut u16) -> c_int {
    if out_port.is_null() {
        return -1;
    }
    let table = fed_listeners().lock();
    match table.listeners.get(&listener) {
        Some(entry) => match entry.listener.local_addr() {
            Ok(addr) => {
                unsafe {
                    *out_port = addr.port();
                }
                0
            }
            Err(_) => -2,
        },
        None => -3,
    }
}

/// Accept one encrypted session; the session handle works with
/// aegis_fed_send/recv/close. Blocking. 0 ok; -2 accept/handshake
/// failure; -3 unknown listener. The global lock is held only to clone
/// the socket + transport handle — never across the handshake.
#[no_mangle]
pub extern "C" fn aegis_fed_accept(listener: u64, out_session: *mut u64) -> c_int {
    if out_session.is_null() {
        return -1;
    }
    let (sock, transport) = {
        let table = fed_listeners().lock();
        let entry = match table.listeners.get(&listener) {
            Some(e) => e,
            None => return -3,
        };
        let sock = match entry.listener.try_clone().and_then(|l| l.accept().map(|(s, _)| s)) {
            Ok(s) => s,
            Err(_) => return -2,
        };
        (sock, entry.transport.clone())
    };
    let session = match transport.accept_socket(sock) {
        Ok(s) => s,
        Err(_) => return -2,
    };
    let mut sessions = fed_sessions().lock();
    // Session ids share one namespace across roles (close is uniform).
    let id = sessions.next_id;
    sessions.next_id += 1;
    sessions.sessions.insert(id, std::sync::Arc::new(parking_lot::Mutex::new(FedSession::Server(session))));
    unsafe {
        *out_session = id;
    }
    0
}

/// Close a listener. 0 ok; -3 unknown listener (double close fails
/// closed). Sessions accepted from it are unaffected.
#[no_mangle]
pub extern "C" fn aegis_fed_listen_close(listener: u64) -> c_int {
    let mut table = fed_listeners().lock();
    if table.listeners.remove(&listener).is_some() {
        0
    } else {
        -3
    }
}

// ============================================================================
// 5. Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pep_init_succeeds() {
        assert_eq!(aegis_pep_init(), 0);
    }

    #[test]
    fn pep_enforce_null_returns_error() {
        unsafe {
            assert_eq!(aegis_pep_enforce(std::ptr::null(), std::ptr::null_mut()), -1);
        }
    }

    #[test]
    fn quota_consume_exhausts_at_default_and_fails_closed() {
        let mut state = PepState {
            quotas: HashMap::new(),
            two_person_rule: false,
            pending_approvals: HashMap::new(),
        };
        for _ in 0..QUOTA_DEFAULT {
            let (remaining, allowed) = quota_consume(&mut state, 0xC0A80199, 1_000_000);
            assert!(allowed);
            assert!(remaining < QUOTA_DEFAULT);
        }
        let (remaining, allowed) = quota_consume(&mut state, 0xC0A80199, 1_000_000);
        assert!(!allowed);
        assert_eq!(remaining, 0);
    }

    #[test]
    fn quota_consume_resets_after_window_and_isolates_sources() {
        let mut state = PepState {
            quotas: HashMap::new(),
            two_person_rule: false,
            pending_approvals: HashMap::new(),
        };
        for _ in 0..QUOTA_DEFAULT {
            assert!(quota_consume(&mut state, 0x0A000001, 2_000_000).1);
        }
        assert!(!quota_consume(&mut state, 0x0A000001, 2_000_000).1);
        // Other source unaffected.
        assert!(quota_consume(&mut state, 0x0A000002, 2_000_000).1);
        // Window rollover restores the exhausted source.
        assert!(quota_consume(&mut state, 0x0A000001, 2_000_000 + QUOTA_WINDOW_MS).1);
    }

    #[test]
    fn two_person_rule_setter_requires_capability() {
        assert_eq!(aegis_pep_set_two_person_rule(1, 0), -3);
        assert_eq!(aegis_pep_set_two_person_rule(1, 1), 0);
        assert_eq!(aegis_pep_set_two_person_rule(0, 1), 0);
    }

    // FED-P2A: Rust federation TLS is real crypto, loopback-proven, still
    // unwired (no FFI, no production caller). Test PKI is issued in-test
    // by rcgen (dev-dependency); production issuance stays operator-owned.
    struct FedTestPki {
        ca_pem: Vec<u8>,
        srv_chain_pem: Vec<u8>,
        srv_key_pem: Vec<u8>,
        cli_chain_pem: Vec<u8>,
        cli_key_pem: Vec<u8>,
        wrong_chain_pem: Vec<u8>,
        wrong_key_pem: Vec<u8>,
        other_ca_pem: Vec<u8>,
    }

    fn fed_leaf(
        ca_cert: &rcgen::Certificate,
        ca_key: &rcgen::KeyPair,
        san: &str,
    ) -> (Vec<u8>, Vec<u8>) {
        let params = rcgen::CertificateParams::new(vec![san.to_string()]).unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, ca_cert, ca_key).unwrap();
        (cert.pem().into_bytes(), key.serialize_pem().into_bytes())
    }

    fn fed_ca() -> (rcgen::Certificate, rcgen::KeyPair) {
        let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        (cert, key)
    }

    fn fed_test_pki() -> FedTestPki {
        let (ca, ca_key) = fed_ca();
        let (ca2, _) = fed_ca();

        let (srv_chain_pem, srv_key_pem) = fed_leaf(&ca, &ca_key, "localhost");
        let (cli_chain_pem, cli_key_pem) = fed_leaf(&ca, &ca_key, "localhost");
        let (wrong_chain_pem, wrong_key_pem) = fed_leaf(&ca, &ca_key, "other.invalid");
        FedTestPki {
            ca_pem: ca.pem().into_bytes(),
            srv_chain_pem,
            srv_key_pem,
            cli_chain_pem,
            cli_key_pem,
            wrong_chain_pem,
            wrong_key_pem,
            other_ca_pem: ca2.pem().into_bytes(),
        }
    }

    fn fed_server_cfg(pki: &FedTestPki) -> federation_tls::TlsConfig {
        federation_tls::TlsConfig {
            cert_chain: vec![pki.srv_chain_pem.clone()],
            private_key: pki.srv_key_pem.clone(),
            trusted_roots: vec![pki.ca_pem.clone()],
            require_client_auth: true,
            server_name: "localhost".to_string(),
        }
    }

    fn fed_client_cfg(pki: &FedTestPki) -> federation_tls::TlsConfig {
        federation_tls::TlsConfig {
            cert_chain: vec![pki.cli_chain_pem.clone()],
            private_key: pki.cli_key_pem.clone(),
            trusted_roots: vec![pki.ca_pem.clone()],
            require_client_auth: true,
            server_name: "localhost".to_string(),
        }
    }

    /// Accept one session on an ephemeral loopback listener in a helper
    /// thread; returns the bound address. The thread echoes one 5-byte
    /// ping back so the handshake + both directions are proven.
    fn fed_spawn_echo_server(
        transport: federation_tls::TlsTransport,
    ) -> (std::net::SocketAddr, std::thread::JoinHandle<bool>) {
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("loopback bind");
        let addr = listener.local_addr().expect("local addr");
        let handle = std::thread::spawn(move || {
            let mut sess = transport.accept(&listener).expect("accept");
            let mut buf = [0u8; 5];
            let mut got = 0;
            while got < 5 {
                match sess.recv(&mut buf[got..]) {
                    Ok(0) => break,
                    Ok(n) => got += n,
                    Err(_) => return false,
                }
            }
            if got != 5 || &buf != b"ping!" {
                return false;
            }
            sess.send(b"pong!").is_ok()
        });
        (addr, handle)
    }

    #[test]
    fn fed_tls_new_rejects_empty_roots() {
        let cfg = federation_tls::TlsConfig {
            trusted_roots: Vec::new(),
            ..Default::default()
        };
        assert!(federation_tls::TlsTransport::new(cfg).is_err());
    }

    #[test]
    fn fed_tls_new_rejects_garbage_roots() {
        let cfg = federation_tls::TlsConfig {
            trusted_roots: vec![b"not a pem".to_vec()],
            ..Default::default()
        };
        assert!(federation_tls::TlsTransport::new(cfg).is_err());
    }

    #[test]
    fn fed_tls_new_rejects_empty_server_name() {
        let pki = fed_test_pki();
        let mut cfg = fed_server_cfg(&pki);
        cfg.server_name = String::new();
        assert!(federation_tls::TlsTransport::new(cfg).is_err());
    }

    #[test]
    fn fed_tls_accept_without_server_identity_fails_closed() {
        // A client-only transport (no chain) connects but must never
        // accept — and must fail FAST, never block on the listener.
        let pki = fed_test_pki();
        let mut cfg = fed_client_cfg(&pki);
        cfg.cert_chain = Vec::new();
        cfg.private_key = Vec::new();
        let client_only = federation_tls::TlsTransport::new(cfg).unwrap();
        assert!(!client_only.has_server_identity());
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("loopback bind");
        assert!(client_only.accept(&listener).is_err());
        // A full transport reports server identity.
        let server = federation_tls::TlsTransport::new(fed_server_cfg(&pki)).unwrap();
        assert!(server.has_server_identity());
    }

    #[test]
    fn fed_tls_loopback_mtls_roundtrip() {
        let pki = fed_test_pki();
        let server = federation_tls::TlsTransport::new(fed_server_cfg(&pki)).unwrap();
        let (addr, handle) = fed_spawn_echo_server(server);
        let client = federation_tls::TlsTransport::new(fed_client_cfg(&pki)).unwrap();
        let mut sess = client.connect(addr).unwrap();
        sess.send(b"ping!").unwrap();
        let mut buf = [0u8; 5];
        let mut got = 0;
        while got < 5 {
            match sess.recv(&mut buf[got..]) {
                Ok(0) => break,
                Ok(n) => got += n,
                Err(e) => panic!("client recv: {e}"),
            }
        }
        assert_eq!(&buf, b"pong!");
        // Both directions authenticated: each side saw a peer chain.
        assert!(sess.peer_certificates().map(|c| !c.is_empty()).unwrap_or(false));
        assert!(handle.join().unwrap());
    }

    #[test]
    fn fed_tls_untrusted_server_rejected() {
        let pki = fed_test_pki();
        let server = federation_tls::TlsTransport::new(fed_server_cfg(&pki)).unwrap();
        let (addr, handle) = fed_spawn_echo_server(server);
        // Client trusts a different CA: handshake must fail.
        let mut bad = fed_client_cfg(&pki);
        bad.trusted_roots = vec![pki.other_ca_pem.clone()];
        let client = federation_tls::TlsTransport::new(bad).unwrap();
        let mut sess = client.connect(addr).unwrap();
        assert!(sess.send(b"ping!").is_err() || {
            let mut buf = [0u8; 5];
            sess.recv(&mut buf).is_err()
        });
        let _ = handle.join();
    }

    #[test]
    fn fed_tls_wrong_hostname_rejected() {
        let pki = fed_test_pki();
        let server = federation_tls::TlsTransport::new(fed_server_cfg(&pki)).unwrap();
        let (addr, handle) = fed_spawn_echo_server(server);
        // Client presents a cert for another name and expects it back:
        // verification of "other.invalid" against the localhost chain fails.
        let mut cfg = fed_client_cfg(&pki);
        cfg.cert_chain = vec![pki.wrong_chain_pem.clone()];
        cfg.private_key = pki.wrong_key_pem.clone();
        cfg.server_name = "other.invalid".to_string();
        let client = federation_tls::TlsTransport::new(cfg).unwrap();
        let mut sess = client.connect(addr).unwrap();
        assert!(sess.send(b"ping!").is_err() || {
            let mut buf = [0u8; 5];
            sess.recv(&mut buf).is_err()
        });
        let _ = handle.join();
    }

    #[test]
    fn fed_tls_missing_client_cert_rejected() {
        let pki = fed_test_pki();
        let server = federation_tls::TlsTransport::new(fed_server_cfg(&pki)).unwrap();
        let (addr, handle) = fed_spawn_echo_server(server);
        // Server requires client auth; this client offers no chain.
        let mut cfg = fed_client_cfg(&pki);
        cfg.cert_chain = Vec::new();
        cfg.private_key = Vec::new();
        let client = federation_tls::TlsTransport::new(cfg).unwrap();
        let mut sess = client.connect(addr).unwrap();
        assert!(sess.send(b"ping!").is_err() || {
            let mut buf = [0u8; 5];
            sess.recv(&mut buf).is_err()
        });
        let _ = handle.join();
    }

    // FED-P2B1: the C ABI proves itself through the same loopback path —
    // connect / send / recv / close over opaque handles, fail-closed codes.
    fn fed_ffi_cstr(s: &str) -> std::ffi::CString {
        std::ffi::CString::new(s).unwrap()
    }

    #[test]
    fn fed_ffi_roundtrip_through_c_abi() {
        let pki = fed_test_pki();
        let server = federation_tls::TlsTransport::new(fed_server_cfg(&pki)).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let echo = std::thread::spawn(move || {
            let mut sess = server.accept(&listener).expect("accept");
            let mut buf = [0u8; 5];
            let mut got = 0;
            while got < 5 {
                match sess.recv(&mut buf[got..]) {
                    Ok(0) => break,
                    Ok(n) => got += n,
                    Err(_) => return false,
                }
            }
            got == 5 && &buf == b"ping!" && sess.send(b"pong!").is_ok()
        });

        let host = fed_ffi_cstr("127.0.0.1");
        let name = fed_ffi_cstr("localhost");
        let mut h: u64 = 0;
        let rc = unsafe {
            aegis_fed_connect(
                host.as_ptr(),
                port,
                pki.ca_pem.as_ptr(), pki.ca_pem.len(),
                pki.cli_chain_pem.as_ptr(), pki.cli_chain_pem.len(),
                pki.cli_key_pem.as_ptr(), pki.cli_key_pem.len(),
                name.as_ptr(),
                &mut h,
            )
        };
        assert_eq!(rc, 0);
        assert_ne!(h, 0);

        let ping = b"ping!";
        assert_eq!(unsafe { aegis_fed_send(h, ping.as_ptr(), ping.len()) }, 0);
        let mut buf = [0u8; 5];
        let mut n: usize = 0;
        assert_eq!(unsafe { aegis_fed_recv(h, buf.as_mut_ptr(), buf.len(), &mut n) }, 0);
        assert_eq!(n, 5);
        assert_eq!(&buf, b"pong!");
        assert_eq!(unsafe { aegis_fed_close(h) }, 0);
        // Double close fails closed, never double-frees.
        assert_eq!(unsafe { aegis_fed_close(h) }, -3);
        assert!(echo.join().unwrap());
    }

    #[test]
    fn fed_ffi_rejects_misuse_with_fail_closed_codes() {
        // Nulls.
        assert_eq!(unsafe { aegis_fed_connect(std::ptr::null(), 1, std::ptr::null(), 0, std::ptr::null(), 0, std::ptr::null(), 0, std::ptr::null(), std::ptr::null_mut()) }, -1);
        let mut h: u64 = 0;
        let host = fed_ffi_cstr("127.0.0.1");
        let name = fed_ffi_cstr("localhost");
        let roots = b"junk".to_vec();
        // Unparseable roots with valid pointers still fail (config, not null).
        assert_eq!(
            unsafe {
                aegis_fed_connect(
                    host.as_ptr(), 1,
                    roots.as_ptr(), roots.len(),
                    std::ptr::null(), 0, std::ptr::null(), 0,
                    name.as_ptr(), &mut h,
                )
            },
            -2
        );
        // Unknown handle on every op.
        let dead: u64 = 0xDEAD_BEEF_F00D;
        assert_eq!(unsafe { aegis_fed_send(dead, b"x".as_ptr(), 1) }, -3);
        let mut buf = [0u8; 1];
        let mut n: usize = 0;
        assert_eq!(unsafe { aegis_fed_recv(dead, buf.as_mut_ptr(), 1, &mut n) }, -3);
        assert_eq!(unsafe { aegis_fed_recv(dead, std::ptr::null_mut(), 1, &mut n) }, -1);
        assert_eq!(unsafe { aegis_fed_close(dead) }, -3);
    }

    // FED-LSTN-085: listener FFI proves itself end to end entirely
    // through the C ABI: listen (loopback-only) -> client connect ->
    // accept -> mTLS both directions -> close. No internal API on the
    // happy path.
    #[test]
    fn fed_ffi_listen_accept_full_duplex() {
        let pki = fed_test_pki();
        eprintln!("DUPLEX: pki ready");
        let mut lis: u64 = 0;
        assert_eq!(
            unsafe {
                aegis_fed_listen(
                    0,
                    pki.ca_pem.as_ptr(), pki.ca_pem.len(),
                    pki.srv_chain_pem.as_ptr(), pki.srv_chain_pem.len(),
                    pki.srv_key_pem.as_ptr(), pki.srv_key_pem.len(),
                    1,
                    &mut lis,
                )
            },
            0
        );
        assert_ne!(lis, 0);
        let mut port: u16 = 0;
        assert_eq!(unsafe { aegis_fed_listen_port(lis, &mut port) }, 0);
        assert_ne!(port, 0);

        // Client connects concurrently: accept blocks by design.
        let ca = pki.ca_pem.clone();
        let chain = pki.cli_chain_pem.clone();
        let key = pki.cli_key_pem.clone();
        let client_thread = std::thread::spawn(move || {
            let host = fed_ffi_cstr("127.0.0.1");
            let name = fed_ffi_cstr("localhost");
            let mut h: u64 = 0;
            let rc = unsafe {
                aegis_fed_connect(
                    host.as_ptr(), port,
                    ca.as_ptr(), ca.len(),
                    chain.as_ptr(), chain.len(),
                    key.as_ptr(), key.len(),
                    name.as_ptr(), &mut h,
                )
            };
            assert_eq!(rc, 0);
            let ping = b"ping!";
            assert_eq!(unsafe { aegis_fed_send(h, ping.as_ptr(), ping.len()) }, 0);
            let mut buf = [0u8; 5];
            let mut n: usize = 0;
            assert_eq!(unsafe { aegis_fed_recv(h, buf.as_mut_ptr(), buf.len(), &mut n) }, 0);
            assert_eq!((n, &buf), (5, b"pong!"));
            assert_eq!(unsafe { aegis_fed_close(h) }, 0);
        });
        let mut srv: u64 = 0;
        assert_eq!(unsafe { aegis_fed_accept(lis, &mut srv) }, 0);
        assert_ne!(srv, 0);
        // Server side: read ping, write pong (proves the accepted
        // session is a fully working duplex session, not a stub).
        let mut buf = [0u8; 5];
        let mut n: usize = 0;
        let mut got = 0;
        while got < 5 {
            assert_eq!(
                unsafe {
                    aegis_fed_recv(
                        srv,
                        buf.as_mut_ptr().add(got),
                        buf.len() - got,
                        &mut n,
                    )
                },
                0
            );
            if n == 0 {
                break;
            }
            got += n;
        }
        assert_eq!(&buf[..got], b"ping!");
        let pong = b"pong!";
        assert_eq!(unsafe { aegis_fed_send(srv, pong.as_ptr(), pong.len()) }, 0);
        assert_eq!(unsafe { aegis_fed_close(srv) }, 0);
        client_thread.join().unwrap();
        assert_eq!(unsafe { aegis_fed_listen_close(lis) }, 0);
        // Double close fails closed.
        assert_eq!(unsafe { aegis_fed_listen_close(lis) }, -3);
    }

    #[test]
    fn fed_ffi_listen_rejects_misuse() {
        let pki = fed_test_pki();
        let mut lis: u64 = 0;
        // Null out-pointer.
        assert_eq!(
            unsafe {
                aegis_fed_listen(
                    0,
                    pki.ca_pem.as_ptr(), pki.ca_pem.len(),
                    pki.srv_chain_pem.as_ptr(), pki.srv_chain_pem.len(),
                    pki.srv_key_pem.as_ptr(), pki.srv_key_pem.len(),
                    1,
                    std::ptr::null_mut(),
                )
            },
            -1
        );
        // Empty chain: no server identity.
        assert_eq!(
            unsafe {
                aegis_fed_listen(
                    0,
                    pki.ca_pem.as_ptr(), pki.ca_pem.len(),
                    std::ptr::null(), 0,
                    std::ptr::null(), 0,
                    1,
                    &mut lis,
                )
            },
            -2
        );
        // Unknown listener on every op.
        let dead: u64 = 0xDEAD_BEEF_F00D;
        let mut sess: u64 = 0;
        let mut port: u16 = 0;
        assert_eq!(unsafe { aegis_fed_accept(dead, &mut sess) }, -3);
        assert_eq!(unsafe { aegis_fed_accept(dead, std::ptr::null_mut()) }, -1);
        assert_eq!(unsafe { aegis_fed_listen_port(dead, &mut port) }, -3);
        assert_eq!(unsafe { aegis_fed_listen_close(dead) }, -3);
    }

    #[test]
    fn approve_validates_input_and_capability() {
        assert_eq!(aegis_pep_approve(0, 7, 1), -3);
        assert_eq!(aegis_pep_approve(991, 7, 0), -3);
        assert_eq!(aegis_pep_approve(991, 7, 1), 0);
        // Cleanup: approvals for a synthetic id must not linger.
        {
            let state = pep_state();
            let mut s = state.lock();
            s.pending_approvals.remove(&991);
        }
    }

    #[test]
    fn high_severity_block_without_approval_escalates_for_approval() {
        assert_eq!(aegis_pep_set_two_person_rule(1, 1), 0);
        let req = PepRequest {
            decision_kind: 61,
            requested_action: ACTION_BLOCK,
            flow_id: 3,
            src_ip: 0xC0A80105,
            dst_ip: 0x08080808,
            src_port: 12345,
            dst_port: 443,
            protocol: 6,
            policy_id: 9,
            severity: 9,
            ctx: PepContext {
                caller_pid: 1,
                caller_capability_mask: 1,
                request_id: 777001,
                policy_version: 0,
            },
        };
        let mut resp = PepResponse {
            decision: 0,
            reason: 0,
            quota_remaining: 0,
            signed_by: 0,
            filter_id: 0,
        };
        unsafe {
            // No approval recorded: must ESCALATE for approval (reason 2),
            // short-circuiting before any adapter/WFP contact.
            assert_eq!(aegis_pep_enforce(&req, &mut resp), 0);
            assert_eq!(resp.decision, DECISION_ESCALATE);
            assert_eq!(resp.reason, 2);
        }
        assert_eq!(aegis_pep_set_two_person_rule(0, 1), 0);
    }

    #[test]
    fn disabling_two_person_rule_drops_pending_approvals() {
        assert_eq!(aegis_pep_set_two_person_rule(1, 1), 0);
        assert_eq!(aegis_pep_approve(992, 7, 1), 0);
        assert_eq!(aegis_pep_set_two_person_rule(0, 1), 0);
        let state = pep_state();
        let s = state.lock();
        assert!(!s.pending_approvals.contains_key(&992));
    }

    #[test]
    fn pep_unblock_without_capability_is_rejected() {
        assert_eq!(aegis_pep_unblock_ip(0xC0A80101, 1, 0, 3), -3);
    }

    #[test]
    fn pep_ip_only_cleanup_is_rejected_even_with_capability() {
        assert_eq!(aegis_pep_unblock_ip(0xC0A80101, 1, 1, 3), -4);
    }

    #[cfg(windows)]
    #[test]
    fn adapter_cache_reuses_hits_and_reprobes_misses_without_sticking() {
        // PEP-ADAPTER-CACHE-073 + EVT-212: a cache miss must re-probe
        // (never stick), a hit must stay live. Honest about the host:
        // ISO hosts miss; a host with a live device hits. Either way the
        // invariant is no-stick/no-wedge.
        let first = adapter_cache::with_adapter(|_| Some(1u64));
        let second = adapter_cache::with_adapter(|_| Some(1u64));
        assert_eq!(first.is_some(), second.is_some());
        if first.is_some() {
            // Live provider on this host: `with_adapter` reusing the cached
            // handle IS the contract. The enforce half is skipped
            // deliberately -- creating real WFP filters from a unit test
            // would mutate the host.
            return;
        }
        // No provider device here: an approved BLOCK must surface as
        // ESCALATE reason 4 through the cache path exactly as the old
        // per-call load did.
        assert_eq!(aegis_pep_set_two_person_rule(0, 1), 0);
        let req = PepRequest {
            decision_kind: 61,
            requested_action: ACTION_BLOCK,
            flow_id: 7,
            src_ip: 0xC0A80177,
            dst_ip: 0x08080808,
            src_port: 12345,
            dst_port: 443,
            protocol: 6,
            policy_id: 7,
            severity: 4,
            ctx: PepContext {
                caller_pid: 1,
                caller_capability_mask: 1,
                request_id: 777002,
                policy_version: 0,
            },
        };
        let mut resp = PepResponse {
            decision: 0,
            reason: 0,
            quota_remaining: 0,
            signed_by: 0,
            filter_id: 0,
        };
        unsafe {
            assert_eq!(aegis_pep_enforce(&req, &mut resp), 0);
            assert_eq!(resp.decision, DECISION_ESCALATE);
            assert_eq!(resp.reason, 4);
        }
    }

    #[test]
    fn wfp_read_events_rejects_invalid_arguments_before_provider() {
        // EVT-211 hermetic guard: argument rejection happens before any
        // provider contact, so this test never opens the device -- ISO
        // hosts, CI, and developer machines stay untouched. A valid-buffer
        // call is intentionally NOT tested here: on a host where the device
        // opens it would drain live kernel telemetry.
        use std::ptr;
        assert_eq!(aegis_pep_read_events(ptr::null_mut(), 16, &mut 0u32), -3);
        let mut buf = [0u8; 4];
        assert_eq!(aegis_pep_read_events(buf.as_mut_ptr(), 0, &mut 0u32), -3);
        assert_eq!(aegis_pep_read_events(buf.as_mut_ptr(), 4, ptr::null_mut()), -3);
    }

    #[test]
    #[ignore = "requires an explicitly isolated WFP provider proof; must not mutate a developer host"]
    fn pep_enforce_low_severity_requires_wfp_adapter() {
        let req = PepRequest {
            decision_kind: 61,
            requested_action: ACTION_BLOCK,
            flow_id: 1,
            src_ip: 0xC0A80101,
            dst_ip: 0x08080808,
            src_port: 12345,
            dst_port: 80,
            protocol: 6,
            policy_id: 1,
            severity: 4,
            ctx: PepContext {
                caller_pid: 1,
                caller_capability_mask: 1,
                request_id: 1,
                policy_version: 0,
            },
        };
            let mut resp = PepResponse {
                decision: 0,
                reason: 0,
                quota_remaining: 0,
                signed_by: 0,
                filter_id: 0,
            };
        unsafe {
            assert_eq!(aegis_pep_enforce(&req, &mut resp), 0);
            assert_eq!(resp.decision, DECISION_ESCALATE);
            assert_eq!(resp.reason, 4); // host-effect adapter unavailable
        }
    }

    #[test]
    fn pep_enforce_no_capability_returns_escalate_with_reason() {
        let req = PepRequest {
            decision_kind: 61,
            requested_action: ACTION_BLOCK,
            flow_id: 2,
            src_ip: 0xC0A80102,
            dst_ip: 0x08080808,
            src_port: 12345,
            dst_port: 80,
            protocol: 6,
            policy_id: 1,
            severity: 4,
            ctx: PepContext {
                caller_pid: 1,
                caller_capability_mask: 0, // no capability
                request_id: 2,
                policy_version: 0,
            },
        };
        let mut resp = PepResponse {
            decision: 99,
            reason: 0,
            quota_remaining: 0,
            signed_by: 0,
            filter_id: 0,
        };
        unsafe {
            assert_eq!(aegis_pep_enforce(&req, &mut resp), 0);
            assert_eq!(resp.decision, DECISION_ESCALATE);
            assert_eq!(resp.reason, 1);
        }
    }

    #[test]
    fn pep_quarantine_no_capability_returns_escalate_with_reason() {
        // QUAR-RCPT-112: quarantine is privilege-gated exactly like block.
        let req = PepRequest {
            decision_kind: 61,
            requested_action: ACTION_QUARANTINE,
            flow_id: 12,
            src_ip: 0xC0A8010A,
            dst_ip: 0x08080808,
            src_port: 12345,
            dst_port: 80,
            protocol: 6,
            policy_id: 1,
            severity: 4,
            ctx: PepContext {
                caller_pid: 1,
                caller_capability_mask: 0, // no capability
                request_id: 12,
                policy_version: 0,
            },
        };
        let mut resp = PepResponse {
            decision: 0,
            reason: 0,
            quota_remaining: 0,
            signed_by: 0,
            filter_id: 0,
        };
        unsafe {
            assert_eq!(aegis_pep_enforce(&req, &mut resp), 0);
            assert_eq!(resp.decision, DECISION_ESCALATE);
            assert_eq!(resp.reason, 1);
            assert_eq!(resp.filter_id, 0);
        }
    }

    #[test]
    fn pep_quarantine_without_adapter_fails_closed_no_filter() {
        // No WFP provider on a dev/CI host: quarantine must surface as
        // ESCALATE reason 4 with no filter, never a bare QUARANTINE
        // decision that the Zig verifier could mistake for enforcement.
        let req = PepRequest {
            decision_kind: 61,
            requested_action: ACTION_QUARANTINE,
            flow_id: 13,
            src_ip: 0xC0A8010B,
            dst_ip: 0x08080808,
            src_port: 12345,
            dst_port: 80,
            protocol: 6,
            policy_id: 1,
            severity: 4,
            ctx: PepContext {
                caller_pid: 1,
                caller_capability_mask: 1,
                request_id: 13,
                policy_version: 0,
            },
        };
        let mut resp = PepResponse {
            decision: 0,
            reason: 0,
            quota_remaining: 0,
            signed_by: 0,
            filter_id: 0,
        };
        unsafe {
            assert_eq!(aegis_pep_enforce(&req, &mut resp), 0);
            assert_eq!(resp.decision, DECISION_ESCALATE);
            assert_eq!(resp.reason, 4); // host-effect adapter unavailable
            assert_eq!(resp.filter_id, 0);
        }
    }

    #[test]
    fn high_severity_quarantine_without_approval_escalates_for_approval() {
        // QUAR-RCPT-112: quarantine clears the same two-person bar as block.
        assert_eq!(aegis_pep_set_two_person_rule(1, 1), 0);
        let req = PepRequest {
            decision_kind: 61,
            requested_action: ACTION_QUARANTINE,
            flow_id: 14,
            src_ip: 0xC0A8010C,
            dst_ip: 0x08080808,
            src_port: 12345,
            dst_port: 443,
            protocol: 6,
            policy_id: 9,
            severity: 9,
            ctx: PepContext {
                caller_pid: 1,
                caller_capability_mask: 1,
                request_id: 777014,
                policy_version: 0,
            },
        };
        let mut resp = PepResponse {
            decision: 0,
            reason: 0,
            quota_remaining: 0,
            signed_by: 0,
            filter_id: 0,
        };
        unsafe {
            // No approval recorded: must ESCALATE for approval (reason 2),
            // short-circuiting before any adapter/WFP contact.
            assert_eq!(aegis_pep_enforce(&req, &mut resp), 0);
            assert_eq!(resp.decision, DECISION_ESCALATE);
            assert_eq!(resp.reason, 2);
            assert_eq!(resp.filter_id, 0);
        }
        assert_eq!(aegis_pep_set_two_person_rule(0, 1), 0);
    }

    #[test]
    fn pep_advisory_action_does_not_require_capability() {
        let req = PepRequest {
            decision_kind: 61,
            requested_action: ACTION_ALERT,
            flow_id: 3,
            src_ip: 0xC0A80103,
            dst_ip: 0x08080808,
            src_port: 12345,
            dst_port: 80,
            protocol: 6,
            policy_id: 1,
            severity: 8,
            ctx: PepContext {
                caller_pid: 1,
                caller_capability_mask: 0,
                request_id: 3,
                policy_version: 0,
            },
        };
        let mut resp = PepResponse {
            decision: 99,
            reason: 0,
            quota_remaining: 0,
            signed_by: 0,
            filter_id: 0,
        };
        unsafe {
            assert_eq!(aegis_pep_enforce(&req, &mut resp), 0);
            assert_eq!(resp.decision, DECISION_ALLOW);
            assert_eq!(resp.reason, 0);
        }
    }

    #[test]
    fn pep_unknown_action_fails_closed_as_authorization_denial() {
        // A requested_action byte that is not a policy.Action ordinal must not
        // be answered with the default DECISION_ALLOW. The sole enforcement
        // authority has to fail closed for anything it cannot classify.
        let req = PepRequest {
            decision_kind: 61,
            requested_action: 0xFF,
            flow_id: 4,
            src_ip: 0xC0A80104,
            dst_ip: 0x08080808,
            src_port: 12345,
            dst_port: 80,
            protocol: 6,
            policy_id: 1,
            severity: 4,
            ctx: PepContext {
                caller_pid: 1,
                caller_capability_mask: 1,
                request_id: 4,
                policy_version: 0,
            },
        };
        let mut resp = PepResponse {
            decision: 99,
            reason: 0,
            quota_remaining: 0,
            signed_by: 0,
            filter_id: 0,
        };
        unsafe {
            assert_eq!(aegis_pep_enforce(&req, &mut resp), 0);
            assert_ne!(resp.decision, DECISION_ALLOW);
            assert_eq!(resp.decision, DECISION_ESCALATE);
            assert_eq!(resp.reason, 6);
        }
    }

    #[test]
    fn quota_remaining_default() {
        let remaining = aegis_pep_quota_remaining(0xC0A80199);
        assert_eq!(remaining, QUOTA_DEFAULT);
    }

    // ============================================================================
    // GAP-001: Policy Signature Verification Tests
    // ============================================================================

    #[test]
    fn sha256_empty_input() {
        let hash = sha256_hash(b"");
        // SHA-256 of empty string
        assert_eq!(
            hash,
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
                0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
                0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
                0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
            ]
        );
    }

    #[test]
    fn sha256_abc() {
        let hash = sha256_hash(b"abc");
        // SHA-256 of "abc"
        assert_eq!(
            hash,
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
                0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
                0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
                0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
            ]
        );
    }

    #[test]
    fn sha256_deterministic() {
        let h1 = sha256_hash(b"test data");
        let h2 = sha256_hash(b"test data");
        assert_eq!(h1, h2);
    }

    #[test]
    fn sha256_different_inputs_different_hashes() {
        let h1 = sha256_hash(b"input1");
        let h2 = sha256_hash(b"input2");
        assert_ne!(h1, h2);
    }

    #[test]
    fn verify_policy_signature_rejects_empty_key() {
        let policy = b"test policy";
        let sig = [1u8; 64];
        let key = [0u8; 32]; // all zeros
        assert!(!verify_policy_signature(policy, &sig, &key));
    }

    #[test]
    fn verify_policy_signature_rejects_empty_sig() {
        let policy = b"test policy";
        let sig = [0u8; 64]; // all zeros
        let key = [1u8; 32];
        assert!(!verify_policy_signature(policy, &sig, &key));
    }

    #[test]
    fn verify_policy_signature_rejects_wrong_key_length() {
        let policy = b"test policy";
        let sig = [1u8; 64];
        let key = [1u8; 16]; // wrong length
        assert!(!verify_policy_signature(policy, &sig, &key));
    }

    #[test]
    fn verify_policy_signature_rejects_wrong_sig_length() {
        let policy = b"test policy";
        let sig = [1u8; 32]; // wrong length
        let key = [1u8; 32];
        assert!(!verify_policy_signature(policy, &sig, &key));
    }

    #[test]
    fn verify_policy_signature_verifies_real_ed25519() {
        use ring::signature;
        use ring::rand::SystemRandom;
        use ring::signature::KeyPair;
        // Generate real Ed25519 key pair
        let pkcs8 = signature::Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let public_key = key_pair.public_key();
        // Sign real policy data
        let policy = b"real policy data for signing";
        let signature_bytes = key_pair.sign(policy);
        // Verify should succeed
        assert!(verify_policy_signature(
            policy,
            signature_bytes.as_ref(),
            public_key.as_ref()
        ));
    }

    #[test]
    fn verify_policy_signature_rejects_wrong_data() {
        use ring::signature;
        use ring::rand::SystemRandom;
        use ring::signature::KeyPair;
        // Generate real Ed25519 key pair
        let pkcs8 = signature::Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let public_key = key_pair.public_key();
        // Sign one message, verify with different message
        let policy1 = b"policy version 1";
        let policy2 = b"policy version 2";
        let signature_bytes = key_pair.sign(policy1);
        // Verify with wrong data should fail
        assert!(!verify_policy_signature(
            policy2,
            signature_bytes.as_ref(),
            public_key.as_ref()
        ));
    }

    #[test]
    fn verify_policy_signature_rejects_wrong_key() {
        use ring::signature;
        use ring::rand::SystemRandom;
        use ring::signature::KeyPair;
        // Generate two different key pairs
        let pkcs8_1 = signature::Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let key_pair_1 = signature::Ed25519KeyPair::from_pkcs8(pkcs8_1.as_ref()).unwrap();
        let pkcs8_2 = signature::Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let key_pair_2 = signature::Ed25519KeyPair::from_pkcs8(pkcs8_2.as_ref()).unwrap();
        // Sign with key1, verify with key2 should fail
        let policy = b"policy signed with key1";
        let signature_bytes = key_pair_1.sign(policy);
        assert!(!verify_policy_signature(
            policy,
            signature_bytes.as_ref(),
            key_pair_2.public_key().as_ref()
        ));
    }

    // POL-SIGN-078: the C ABI proves itself through real sign/verify and
    // every fail-closed code. Wired via src/policy/policy_signing.zig
    // (verifyViaRust); key custody remains per ADR-0005 Q3.
    #[test]
    fn policy_verify_ffi_roundtrip() {
        use ring::signature;
        use ring::rand::SystemRandom;
        use ring::signature::KeyPair;
        let pkcs8 = signature::Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let policy = b"policy ir bytes for ffi roundtrip";
        let sig = key_pair.sign(policy);
        let rc = unsafe {
            aegis_policy_verify(
                policy.as_ptr(), policy.len(),
                sig.as_ref().as_ptr(), sig.as_ref().len(),
                key_pair.public_key().as_ref().as_ptr(), key_pair.public_key().as_ref().len(),
            )
        };
        assert_eq!(rc, 0);
    }

    #[test]
    fn policy_verify_ffi_rejects_misuse() {
        use ring::signature;
        use ring::rand::SystemRandom;
        use ring::signature::KeyPair;
        let pkcs8 = signature::Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let policy = b"policy ir bytes";
        let sig = key_pair.sign(policy);
        let pk = key_pair.public_key();
        // Nulls fail closed.
        assert_eq!(
            unsafe {
                aegis_policy_verify(
                    std::ptr::null(), policy.len(),
                    sig.as_ref().as_ptr(), sig.as_ref().len(),
                    pk.as_ref().as_ptr(), pk.as_ref().len(),
                )
            },
            -1
        );
        // Empty policy bytes verify nothing.
        assert_eq!(
            unsafe {
                aegis_policy_verify(
                    policy.as_ptr(), 0,
                    sig.as_ref().as_ptr(), sig.as_ref().len(),
                    pk.as_ref().as_ptr(), pk.as_ref().len(),
                )
            },
            -2
        );
        // Tampered byte fails crypto.
        let mut bad = policy.to_vec();
        bad[0] ^= 0xFF;
        assert_eq!(
            unsafe {
                aegis_policy_verify(
                    bad.as_ptr(), bad.len(),
                    sig.as_ref().as_ptr(), sig.as_ref().len(),
                    pk.as_ref().as_ptr(), pk.as_ref().len(),
                )
            },
            -2
        );
        // Truncated signature fails shape checks.
        assert_eq!(
            unsafe {
                aegis_policy_verify(
                    policy.as_ptr(), policy.len(),
                    sig.as_ref().as_ptr(), 32,
                    pk.as_ref().as_ptr(), pk.as_ref().len(),
                )
            },
            -2
        );
    }
}
