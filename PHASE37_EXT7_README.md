# AEGIS NIDS - Phase 37 Extension 7: Full T1055 Process Injection Detection

**Risk**: MEDIUM | **Phase 37 Extension** | **Status: HOST-VERIFIED + 27 tests**

Real-time detection of process injection techniques using ETW Thread provider
and Windows API hook patterns. Replaces the heuristic-based approach in Ext 3
with actual event-driven detection.

## MITRE ATT&CK T1055 Coverage

| Technique | MITRE | Detection Pattern | Confidence |
|---|---|---|---|
| CreateRemoteThread | T1055.001 | Cross-process thread creation | 70% |
| DLL Injection | T1055.001 | VirtualAllocEx + WriteProcessMemory + CreateRemoteThread chain | 95% |
| PE Injection | T1055.002 | VirtualAllocEx RWX + CreateRemoteThread | 90% |
| Process Hollowing | T1055.012 | CreateProcess(SUSPENDED) + WriteProcessMemory + ResumeThread | (future) |
| Thread Hijacking | T1055.003 | SetThreadContext on remote thread | 80% |
| APC Injection | T1055.004 | QueueUserAPC to thread in different process | 85% |

## Ext 3 vs Ext 7 Comparison

| Feature | Ext 3 (Heuristic) | Ext 7 (Real-time) |
|---|---|---|
| Detection method | Image-path patterns | Actual API call events |
| Coverage | 2 patterns | 6 patterns |
| False positives | Higher (temp folder = suspicious) | Lower (actual cross-process API) |
| Chain correlation | None | 10s window for multi-step chains |
| Confidence levels | Binary (detected/not) | 60-95% graded |

## 6 Demo Scenarios (all PASS)

1. **kill-switch-off** — Disabled, no alerts
2. **create-remote-thread** — T1055.001, confidence=70
3. **virtual-alloc-rwx** — T1055.002, confidence=60
4. **apc-injection** — T1055.004, confidence=85
5. **dll-injection-chain** — 3-step chain, confidence=95
6. **pe-injection-chain** — RWX+CRT, confidence=90

## Quick Start

```bash
zig test core/injection_detector.zig -lc          # 27 tests pass
zig build-exe core/injection_detector_cli.zig -lc
./injection_detector_cli demo                      # 6/6 scenarios pass
```

## Verification

```
[ ] zig test core/injection_detector.zig -lc            -> 27 tests passed
[ ] zig build-exe core/injection_detector_cli.zig -lc -> clean compile
[ ] ./injection_detector_cli demo                      -> 6/6 PASS
```
