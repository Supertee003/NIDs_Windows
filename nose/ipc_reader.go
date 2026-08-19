// =====================================================================
// ipc_reader.go - AEGIS NOSE IPC Input Reader
// Reads DEFCON level and threat data from Bridge via JSON status file
// =====================================================================
package main

import (
        "encoding/json"
        "fmt"
        "os"
        "sync"
        "time"
)

type BridgeStatus struct {
        DEFCONLevel   int    `json:"defcon_level"`
        DEFCONLabel   string `json:"defcon_label"`
        EventCount    int    `json:"event_count"`
        DroppedCount  int    `json:"dropped_count"`
        CriticalCount int    `json:"critical_count"`
        BlockedIPs    int    `json:"blocked_ips"`
        KernelThreats int    `json:"kernel_threats"`
        TotalAlerts   int    `json:"total_alerts"`
        Uptime        int64  `json:"uptime_ms"`
}

type IPCReader struct {
        mu        sync.RWMutex
        status    BridgeStatus
        lastMod   time.Time
        filePath  string
        pollMs    int
        available bool
}

func NewIPCReader(filePath string, pollMs int) *IPCReader {
        if pollMs <= 0 { pollMs = 500 }
        return &IPCReader{
                filePath: filePath,
                pollMs:   pollMs,
                status: BridgeStatus{DEFCONLevel: 5, DEFCONLabel: "SAFE"},
        }
}

func (r *IPCReader) Start() { go r.pollLoop() }

func (r *IPCReader) GetStatus() BridgeStatus {
        r.mu.RLock()
        defer r.mu.RUnlock()
        return r.status
}

func (r *IPCReader) IsAvailable() bool {
        r.mu.RLock()
        defer r.mu.RUnlock()
        return r.available
}

func (r *IPCReader) pollLoop() {
        ticker := time.NewTicker(time.Duration(r.pollMs) * time.Millisecond)
        defer ticker.Stop()
        for range ticker.C { r.readStatusFile() }
}

func (r *IPCReader) readStatusFile() {
        info, err := os.Stat(r.filePath)
        if err != nil {
                r.mu.Lock()
                r.available = false
                r.mu.Unlock()
                return
        }
        modTime := info.ModTime()
        if modTime.Equal(r.lastMod) { return }
        data, err := os.ReadFile(r.filePath)
        if err != nil { return }
        var status BridgeStatus
        if err := json.Unmarshal(data, &status); err != nil { return }
        if status.DEFCONLevel < 1 || status.DEFCONLevel > 5 {
                status.DEFCONLevel = 5
                status.DEFCONLabel = "SAFE"
        }
        r.mu.Lock()
        r.status = status
        r.available = true
        r.lastMod = modTime
        r.mu.Unlock()
        fmt.Fprintf(os.Stderr, "[NOSE IPC] DEFCON=%d (%s) events=%d blocked=%d\n",
                status.DEFCONLevel, status.DEFCONLabel, status.EventCount, status.BlockedIPs)
}
