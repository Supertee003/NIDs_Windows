# AEGIS Failure Model (STEP 0 — Baseline Freeze)

## Failure Modes by Layer

### Layer 1: Sensors
| Failure | Current Behavior | Correct? | Fix Needed |
|---------|------------------|----------|------------|
| WFP driver not loaded | Retries every 10s (overlapped I/O) | ✅ | None |
| Named pipe creation fails | Exponential backoff (1s→30s) | ✅ | None |
| Minifilter port unavailable | Retries every 10s | ✅ | None |
| HIDS process scan fails | Sleeps 30s, retries | ⚠️ (stub) | Wire to ETW/WMI |
| Sensor → Fabric submit fails | Logs warning, continues | ✅ | None |

### Layer 2: Nose Contract (Event Fabric)
| Failure | Current Behavior | Correct? | Fix Needed |
|---------|------------------|----------|------------|
| Invalid event (wrong magic) | Returns .rejected, increments counter | ✅ | None |
| Queue full (overflow) | Drops event, increments counter | ⚠️ | Add backpressure (STEP 16) |
| Event Fabric not initialized | Returns .not_initialized | ✅ | None |
| CRC32 mismatch (wire) | Returns .rejected | ✅ | None |

### Layer 3: Detection
| Failure | Current Behavior | Correct? | Fix Needed |
|---------|------------------|----------|------------|
| AC Engine panic | catch → fail-open (return true) | ⚠️ | Should be fail-closed for Block rules |
| Rust Shield not loaded | Fail-open (validatePayloadSafety returns true) | ⚠️ | P-01: logged as CRITICAL |
| DetectionManager error | Returns DetectionResult.error | ✅ | None |
| Ruleset null (not loaded) | Fail-open (return true) | ⚠️ | Should be fail-closed |

### Layer 4: Policy
| Failure | Current Behavior | Correct? | Fix Needed |
|---------|------------------|----------|------------|
| No policy rule matches | Returns default_action (allow) | ✅ | None |
| DEFCON 1 + match | Escalates to BLOCK | ✅ | None |
| Policy reload during evaluation | RwLock protects fn pointers | ✅ | None |

### Layer 5: Enforcement (PEP)
| Failure | Current Behavior | Correct? | Fix Needed |
|---------|------------------|----------|------------|
| WFP device not open | block_ip returns false → .failed | ✅ | None |
| Block IP table full (256) | addBlockedIp returns false | ⚠️ | Use HashMap (like rate-limit) |
| Quarantine action | Returns .not_implemented | ⚠️ | Implement or remove |
| Python Brain bypasses PEP | Calls netsh directly | ❌ | Fix: route through PEP |

### Layer 6: Forensics
| Failure | Current Behavior | Correct? | Fix Needed |
|---------|------------------|----------|------------|
| Log file write fails | Logs warning, continues | ⚠️ | Should alert operator |
| Log rotation fails | Silently catches error | ❌ | Log rotation failure |
| Disk full | WriteFile fails silently | ❌ | Add disk space check |
| Payload capture fails | Returns null, continues | ✅ | None |

### Layer 7: Concurrency
| Failure | Current Behavior | Correct? | Fix Needed |
|---------|------------------|----------|------------|
| Thread spawn fails | Logs warning, continues without thread | ✅ | None |
| Shutdown race (fn pointers) | RwLock protects | ✅ | None |
| Rule reload TOCTOU | Hazard-pointer pattern (retain/release) | ✅ | None |
| UDP send fails | Spool queue (1000 events) + drain thread | ✅ | None |
| Spool queue full | Drops oldest + counter | ⚠️ | Monitor drops metric |

### Layer 8: Cross-Language
| Failure | Current Behavior | Correct? | Fix Needed |
|---------|------------------|----------|------------|
| C++ DLL not found | Runs without bridge (degraded) | ✅ | None |
| Rust DLL not found | Fail-open (CRITICAL log) | ⚠️ | P-01 fixed |
| DLL signature mismatch | No verification (B-02 open) | ❌ | Add WinVerifyTrust |
| IPC struct ABI drift | magic+version check (B-05) | ✅ | None |
| Ring buffer data race | std::mutex (B-06 fixed) | ✅ | None |

## Failure Classification

### Fail-Open (risky — may miss attacks)
| Component | Condition | Risk |
|-----------|-----------|------|
| AC Engine panic | catch → return true | Medium — attack may pass |
| Rust Shield not loaded | validatePayloadSafety returns true | High — Tier-3 bypassed |
| Ruleset null | return true | High — no detection |
| Detection error | return true | Medium |

### Fail-Closed (safe — may block benign traffic)
| Component | Condition | Risk |
|-----------|-----------|------|
| SDDL failure | Refuse to create pipe | Low — no sensor, but safe |
| Rate-limit HashMap OOM | Reject connection | Low — better safe |
| PEP block_ip fails | Return .failed | Low — logged for retry |

## Backpressure (not yet implemented — STEP 16)

```
Queue 0-70%   → NORMAL (all priorities processed)
Queue 70-85%  → MONITOR (log warning)
Queue 85-95%  → PRIORITIZE SECURITY (drop LOW priority)
Queue 95-100%  → EMERGENCY (drop LOW+NORMAL, keep HIGH only)
Queue 100%    → EMERGENCY MODE (reject new submissions, alert)
```

## Acceptance Criteria

- [x] All failure modes documented
- [x] Fail-open vs fail-closed classified
- [ ] Backpressure implemented (STEP 16)
- [ ] Python Brain PEP bypass fixed
- [ ] Block IP table → HashMap
- [ ] Quarantine implemented or removed
