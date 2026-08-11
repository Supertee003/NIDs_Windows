// windows_perf.go — AEGIS NIDS Performance Monitor (Layer 5: Go)
//
// 3-goroutine architecture for system resource monitoring:
//   Goroutine 1: CPU/Memory sampler    — Collects process metrics every 1s
//   Goroutine 2: Network I/O counter   — Tracks bytes/packets per interface
//   Goroutine 3: Alert rate calculator — Computes alerts/sec and throughput
//
// Metrics are exposed via named pipe for Python brain consumption
// and via gRPC for Vaadin UI dashboard.
//
// Build: go build -o aegis_perf.exe
// Language: Go 1.22+

package main

/*
#cgo LDFLAGS$ -Laegis_shield -laegis_shield
#include <stdint.h>

// C-ABI declarations from Rust Semi-NIDS engine (libaegis_shield.so/.dll)
extern int32_t aegis_semi_nids_init(void);
extern void   aegis_semi_nids_update_load(uint8_t cpu_pct, uint8_t queue_pct, uint64_t pps);
extern int32_t aegis_semi_nids_fail_open_status(uint8_t* out_active, uint8_t* out_cpu_pct, uint8_t* out_queue_pct);
extern void   aegis_semi_nids_shutdown(void);
*/
import "C"

import (
        "context"
        "encoding/json"
        "fmt"
        "log"
        "os"
        "sync"
        "sync/atomic"
        "syscall"
        "time"
        "unsafe"
)

// ─── Windows API imports ───

var (
        modkernel32 = syscall.NewLazyDLL("kernel32.dll")
        modpsapi    = syscall.NewLazyDLL("psapi.dll")

        procGetProcessMemoryInfo = modpsapi.NewLazyProc("GetProcessMemoryInfo")
        procGetSystemTimes       = modkernel32.NewLazyProc("GetSystemTimes")
        procGetCurrentProcess    = modkernel32.NewLazyProc("GetCurrentProcess")
)

// ─── Types ───

// PerfMetrics holds all collected performance metrics.
type PerfMetrics struct {
        // CPU
        CPUUsagePercent float64 `json:"cpu_usage_percent"`

        // Memory
        WorkingSetMB    float64 `json:"working_set_mb"`
        PeakWorkingMB   float64 `json:"peak_working_mb"`
        PrivateBytesMB  float64 `json:"private_bytes_mb"`

        // Network I/O
        BytesInPerSec   float64 `json:"bytes_in_per_sec"`
        BytesOutPerSec  float64 `json:"bytes_out_per_sec"`
        PacketsInPerSec float64 `json:"packets_in_per_sec"`
        PacketsOutPerSec float64 `json:"packets_out_per_sec"`

        // NIDS-specific
        AlertsPerSec    float64 `json:"alerts_per_sec"`
        PacketsPerSec   float64 `json:"packets_per_sec"`
        DroppedPerSec   float64 `json:"dropped_per_sec"`

        // Timestamp
        TimestampMs     int64   `json:"timestamp_ms"`
}

// PROCESS_MEMORY_COUNTERS_EX for GetProcessMemoryInfo
type PROCESS_MEMORY_COUNTERS_EX struct {
        CB                         uint32
        PageFaultCount             uint32
        PeakWorkingSetSize         uintptr
        WorkingSetSize             uintptr
        QuotaPeakPagedPoolUsage    uintptr
        QuotaPagedPoolUsage        uintptr
        QuotaPeakNonPagedPoolUsage uintptr
        QuotaNonPagedPoolUsage     uintptr
        PagefileUsage              uintptr
        PeakPagefileUsage          uintptr
        PrivateUsage               uintptr
}

// ─── Global Metrics State ───

var (
        metrics      PerfMetrics
        metricsMutex sync.RWMutex

        // Atomic counters for rate calculations
        prevBytesIn    atomic.Int64
        prevBytesOut   atomic.Int64
        prevPacketsIn  atomic.Int64
        prevPacketsOut atomic.Int64
        prevAlerts     atomic.Int64
        prevDropped    atomic.Int64
)

// ─── Goroutine 1: CPU/Memory Sampler ───

func cpuMemorySampler(ctx context.Context, interval time.Duration) {
        log.Println("[Goroutine 1] CPU/Memory sampler started")

        ticker := time.NewTicker(interval)
        defer ticker.Stop()

        // Get current process handle
        hProcess, _, _ := procGetCurrentProcess.Call()
        if hProcess == 0 {
                log.Println("[Goroutine 1] ERROR: GetCurrentProcess failed")
                return
        }

        var prevIdle, prevKernel, prevUser uint64
        firstRun := true

        for {
                select {
                case <-ctx.Done():
                        log.Println("[Goroutine 1] Stopped")
                        return
                case <-ticker.C:
                }

                // ── CPU Usage (via GetSystemTimes) ──
                var idle, kernel, user syscall.Filetime
                ret, _, _ := procGetSystemTimes.Call(
                        uintptr(unsafe.Pointer(&idle)),
                        uintptr(unsafe.Pointer(&kernel)),
                        uintptr(unsafe.Pointer(&user)),
                )
                if ret != 0 && !firstRun {
                        idleVal := ftToUint64(idle)
                        kernelVal := ftToUint64(kernel)
                        userVal := ftToUint64(user)

                        idleDiff := idleVal - prevIdle
                        kernelDiff := kernelVal - prevKernel
                        userDiff := userVal - prevUser
                        totalDiff := kernelDiff + userDiff

                        if totalDiff > 0 {
                                cpuUsage := float64(totalDiff-idleDiff) / float64(totalDiff) * 100.0
                                metricsMutex.Lock()
                                metrics.CPUUsagePercent = cpuUsage
                                metricsMutex.Unlock()
                        }
                }
                prevIdle = ftToUint64(idle)
                prevKernel = ftToUint64(kernel)
                prevUser = ftToUint64(user)
                firstRun = false

                // ── Memory Usage (via GetProcessMemoryInfo) ──
                var mc PROCESS_MEMORY_COUNTERS_EX
                mc.CB = uint32(unsafe.Sizeof(mc))
                ret, _, _ = procGetProcessMemoryInfo.Call(
                        hProcess,
                        uintptr(unsafe.Pointer(&mc)),
                        uintptr(mc.CB),
                )
                if ret != 0 {
                        metricsMutex.Lock()
                        metrics.WorkingSetMB = float64(mc.WorkingSetSize) / (1024 * 1024)
                        metrics.PeakWorkingMB = float64(mc.PeakWorkingSetSize) / (1024 * 1024)
                        metrics.PrivateBytesMB = float64(mc.PrivateUsage) / (1024 * 1024)
                        metricsMutex.Unlock()
                }
        }
}

// ─── Goroutine 2: Network I/O Counter ───

func networkIOCounter(ctx context.Context, interval time.Duration) {
        log.Println("[Goroutine 2] Network I/O counter started")

        ticker := time.NewTicker(interval)
        defer ticker.Stop()

        // Previous values for rate calculation
        var prevInBytes, prevOutBytes int64
        var prevInPkts, prevOutPkts int64
        firstRun := true

        for {
                select {
                case <-ctx.Done():
                        log.Println("[Goroutine 2] Stopped")
                        return
                case <-ticker.C:
                }

                // Read current counters from IPC bridge (via named pipe or shared memory)
                // In production, this reads from the WFP driver stats IOCTL
                curInBytes := prevBytesIn.Load()
                curOutBytes := prevBytesOut.Load()
                curInPkts := prevPacketsIn.Load()
                curOutPkts := prevPacketsOut.Load()

                if !firstRun {
                        elapsed := interval.Seconds()
                        metricsMutex.Lock()
                        metrics.BytesInPerSec = float64(curInBytes-prevInBytes) / elapsed
                        metrics.BytesOutPerSec = float64(curOutBytes-prevOutBytes) / elapsed
                        metrics.PacketsInPerSec = float64(curInPkts-prevInPkts) / elapsed
                        metrics.PacketsOutPerSec = float64(curOutPkts-prevOutPkts) / elapsed
                        metricsMutex.Unlock()
                }

                prevInBytes = curInBytes
                prevOutBytes = curOutBytes
                prevInPkts = curInPkts
                prevOutPkts = curOutPkts
                firstRun = false
        }
}

// ─── Goroutine 3: Alert Rate Calculator ───

func alertRateCalculator(ctx context.Context, interval time.Duration) {
        log.Println("[Goroutine 3] Alert rate calculator started")

        ticker := time.NewTicker(interval)
        defer ticker.Stop()

        var prevAlerts, prevDropped, prevPackets int64
        firstRun := true

        for {
                select {
                case <-ctx.Done():
                        log.Println("[Goroutine 3] Stopped")
                        return
                case <-ticker.C:
                }

                curAlerts := prevAlerts.Load()  // From Rust shield via IPC
                curDropped := prevDropped.Load() // From WFP driver via IPC
                curPackets := prevPacketsIn.Load()

                if !firstRun {
                        elapsed := interval.Seconds()
                        metricsMutex.Lock()
                        metrics.AlertsPerSec = float64(curAlerts-prevAlerts) / elapsed
                        metrics.PacketsPerSec = float64(curPackets-prevPackets) / elapsed
                        metrics.DroppedPerSec = float64(curDropped-prevDropped) / elapsed
                        metrics.TimestampMs = time.Now().UnixMilli()
                        metricsMutex.Unlock()
                }

                prevAlerts = curAlerts
                prevDropped = curDropped
                prevPackets = curPackets
                firstRun = false
        }
}

// ─── Named Pipe Server (exposes metrics to Python/Java) ───

func namedPipeServer(ctx context.Context, pipeName string) {
        log.Printf("[NamedPipe] Listening on %s", pipeName)

        for {
                select {
                case <-ctx.Done():
                        return
                default:
                }

                // Create named pipe
                pipe, err := os.OpenFile(pipeName, os.O_WRONLY|os.O_CREATE, 0600)
                if err != nil {
                        // On Windows, use syscall.CreateNamedPipe instead
                        time.Sleep(100 * time.Millisecond)
                        continue
                }

                metricsMutex.RLock()
                data, _ := json.Marshal(&metrics)
                metricsMutex.RUnlock()

                pipe.Write(data)
                pipe.Write([]byte("\n"))
                pipe.Close()

                time.Sleep(500 * time.Millisecond)
        }
}

// ─── Utility ───

func ftToUint64(ft syscall.Filetime) uint64 {
        return uint64(ft.HighDateTime)<<32 | uint64(ft.LowDateTime)
}

// ─── Main ───

func main() {
        log.SetFlags(log.LstdFlags | log.Lmicroseconds)
        log.Println("AEGIS Performance Monitor starting...")

        // Initialize Rust Semi-NIDS engine via cgo
        rc := C.aegis_semi_nids_init()
        if rc != 0 {
                log.Println("WARNING: Semi-NIDS engine init failed (running without adaptive load feedback)")
        } else {
                log.Println("Semi-NIDS engine initialized — will push load metrics every 5s")
        }

        ctx, cancel := context.WithCancel(context.Background())
        defer func() {
                cancel()
                C.aegis_semi_nids_shutdown()
        }()

        // Launch 3 goroutines
        interval := 1 * time.Second
        go cpuMemorySampler(ctx, interval)
        go networkIOCounter(ctx, interval)
        go alertRateCalculator(ctx, interval)

        // Launch named pipe server for metrics export
        go namedPipeServer(ctx, `\\.\pipe\AegisPerfMetrics`)

        // Print metrics to console every 5 seconds
        consoleTicker := time.NewTicker(5 * time.Second)
        defer consoleTicker.Stop()

        for {
                select {
                case <-consoleTicker.C:
                        // ── Push CPU/Queue metrics to Rust Semi-NIDS engine (cgo FFI) ──
                        // This allows the Rust engine to activate fail-open (Property 2)
                        // when the system is overloaded.
                        metricsMutex.RLock()
                        cpuPct := uint8(metrics.CPUUsagePercent)
                        if cpuPct > 100 { cpuPct = 100 }
                        // Estimate queue fill from dropped/alerts ratio (simplified)
                        queuePct := uint8(0)
                        if metrics.PacketsPerSec > 0 && metrics.DroppedPerSec > 0 {
                                ratio := metrics.DroppedPerSec / metrics.PacketsPerSec * 100.0
                                if ratio > 100 { ratio = 100 }
                                queuePct = uint8(ratio)
                        }
                        pps := uint64(metrics.PacketsPerSec)
                        metricsMutex.RUnlock()

                        C.aegis_semi_nids_update_load(C.uint8_t(cpuPct), C.uint8_t(queuePct), C.uint64_t(pps))

                        metricsMutex.RLock()
                        fmt.Printf("CPU: %.1f%% | Mem: %.1f MB | In: %.0f B/s | Alerts: %.1f/s | Pkts: %.1f/s | Load→Rust: cpu=%d%%,q=%d%%\n",
                                metrics.CPUUsagePercent,
                                metrics.WorkingSetMB,
                                metrics.BytesInPerSec,
                                metrics.AlertsPerSec,
                                metrics.PacketsPerSec,
                                cpuPct, queuePct,
                        )
                        metricsMutex.RUnlock()
                }
        }
}
