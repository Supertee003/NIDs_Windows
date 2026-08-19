//! AEGIS Shield - Tier-3 FFI Layer
//! Provides C-compatible interface for the AEGIS NIDS scoring and validation engine.

use std::os::raw::c_int;

/// Opaque handle for the AEGIS scoring engine
pub struct AegisEngine {
    initialized: bool,
    threshold: f64,
}

/// FFI: Create a new AEGIS scoring engine instance
#[no_mangle]
pub extern "C" fn aegis_engine_create(threshold: f64) -> *mut AegisEngine {
    let engine = Box::new(AegisEngine {
        initialized: true,
        threshold,
    });
    Box::into_raw(engine)
}

/// FFI: Destroy an AEGIS scoring engine instance
#[no_mangle]
pub unsafe extern "C" fn aegis_engine_destroy(engine: *mut AegisEngine) {
    if !engine.is_null() {
        let _ = Box::from_raw(engine);
    }
}

/// FFI: Score a threat event, returns score (0-100) or -1 on error
#[no_mangle]
pub unsafe extern "C" fn aegis_score_event(
    engine: *const AegisEngine,
    severity: c_int,
    confidence: f64,
) -> c_int {
    if engine.is_null() {
        return -1;
    }
    let eng = &*engine;
    if !eng.initialized {
        return -1;
    }
    let score = (severity as f64 * confidence * 10.0).min(100.0);
    score as c_int
}

/// FFI: Check if score exceeds threshold
#[no_mangle]
pub unsafe extern "C" fn aegis_is_threat(
    engine: *const AegisEngine,
    score: c_int,
) -> c_int {
    if engine.is_null() {
        return 0;
    }
    let eng = &*engine;
    if (score as f64) >= eng.threshold {
        1
    } else {
        0
    }
}