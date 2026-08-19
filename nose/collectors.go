package main

// =====================================================================
// collectors.go — AEGIS NOSE v5.0 Data Collectors
// =====================================================================
//  v5.0: "จมูกดมกลิ่นหาความผิดปกติ"
//  เพิ่ม: Top Talkers, Protocol Distribution, Raw Event Stream
//
//  3 Goroutine Collectors → Channels → bubbletea Model → TUI Render
//    1. resourceCollector  — System Health (enhanced: CPU%, Goroutines, GC)
//    2. trafficCollector   — Network (enhanced: Top Talkers, Protocol Dist)
//    3. threatCollector    — Raw Event Stream + Threat Map
// =====================================================================

import (
        "bufio"
        "encoding/json"
        "fmt"
        "os"
        "runtime"
        "sort"
        "time"
)

// ── Data Structures ──

// ResourceData — system health metrics (v5.0: enhanced)
type ResourceData struct {
        AllocMB     uint64 `json:"alloc_mb"`
        SysMB       uint64 `json:"sys_mb"`
        HeapObjects uint64 `json:"heap_objects"`
        NumGC       uint32 `json:"num_gc"`
        Goroutines  int    `json:"goroutines"`
        CPUCores    int    `json:"cpu_cores"`
        GoVersion   string `json:"go_version"`
        OS          string `json:"os"`
        Arch        string `json:"arch"`
        UptimeSecs  int64  `json:"uptime_secs"`
        // v5.0: Additional health metrics
        HeapInUseMB uint64 `json:"heap_inuse_mb"`  // Heap in-use MB
        StackInUseMB uint64 `json:"stack_inuse_mb"` // Stack in-use MB
        NumCPUUsed  int    `json:"cpu_used_pct"`    // Estimated CPU usage %
        GCPauseMs   uint64 `json:"gc_pause_ms"`     // Last GC pause in ms
}

// TopTalkerEntry — IP with highest bandwidth
type TopTalkerEntry struct {
        IP       string  `json:"ip"`
        RxBytes  int64   `json:"rx_bytes"`
        TxBytes  int64   `json:"tx_bytes"`
        Total    int64   `json:"total"`
}

// ProtocolEntry — protocol distribution
type ProtocolEntry struct {
        Name  string `json:"name"`
        Count int64  `json:"count"`
}

// TrafficData — network traffic metrics (v5.0: enhanced)
type TrafficData struct {
        RxPktsPerSec  int64   `json:"rx_pkts_sec"`
        TxPktsPerSec  int64   `json:"tx_pkts_sec"`
        ActiveConns   int64   `json:"active_conns"`
        RxBytesPerSec float64 `json:"rx_bytes_sec"`
        TxBytesPerSec float64 `json:"tx_bytes_sec"`
        TotalPkts     int64   `json:"total_pkts"`
        // v5.0: Enhanced network data
        TopTalkers    []TopTalkerEntry  `json:"top_talkers"`
        Protocols     []ProtocolEntry   `json:"protocols"`
        TCPCount      int64             `json:"tcp_count"`
        UDPCount      int64             `json:"udp_count"`
        ICMPCount     int64             `json:"icmp_count"`
}

// ThreatData — threat intelligence + raw event stream
type ThreatData struct {
        UniqueThreats  int            `json:"unique_threats"`
        ThreatMap      map[string]int `json:"threat_map"`
        LastAttack     string         `json:"last_attack"`
        TotalEvents    int            `json:"total_events"`
        LastAttackTime time.Time      `json:"last_attack_time"`
        // v5.0: Raw event stream (ring buffer of recent events)
        RawStream      []StreamEntry  `json:"raw_stream"`
}

// StreamEntry — single raw event for the sniffing stream
type StreamEntry struct {
        Timestamp string `json:"timestamp"`
        Source    string `json:"source"`
        EventType string `json:"event_type"`
        Detail    string `json:"detail"`
}

// NoseOutput — JSON output to stderr (for Bridge/Brain)
type NoseOutput struct {
        Timestamp string       `json:"timestamp"`
        Resource  ResourceData `json:"resource"`
        Traffic   TrafficData  `json:"traffic"`
        Threats   ThreatData   `json:"threats"`
}

// ThreatEntry — for sorted threat display
type ThreatEntry struct {
        Name  string
        Count int
}

// ── Goroutine 1: Resource Collector ──
// v5.0: เพิ่ม HeapInUse, StackInUse, GCPauseMs
func resourceCollector(ch chan<- ResourceData, startTime time.Time) {
        goVer := runtime.Version()
        goOS := runtime.GOOS
        goArch := runtime.GOARCH
        cpuCores := runtime.NumCPU()

        var m runtime.MemStats
        for {
                runtime.ReadMemStats(&m)
                ch <- ResourceData{
                        AllocMB:      m.Alloc / 1024 / 1024,
                        SysMB:        m.Sys / 1024 / 1024,
                        HeapObjects:  m.HeapObjects,
                        NumGC:        m.NumGC,
                        Goroutines:   runtime.NumGoroutine(),
                        CPUCores:     cpuCores,
                        GoVersion:    goVer,
                        OS:           goOS,
                        Arch:         goArch,
                        UptimeSecs:   int64(time.Since(startTime).Seconds()),
                        HeapInUseMB:  m.HeapInuse / 1024 / 1024,
                        StackInUseMB: m.StackInuse / 1024 / 1024,
                        GCPauseMs:    gcPauseAvg(m.PauseTotalNs, m.NumGC),
                }
                time.Sleep(2 * time.Second)
        }
}

// gcPauseAvg — safe average GC pause (avoids divide-by-zero when NumGC=0)
func gcPauseAvg(pauseTotalNs uint64, numGC uint32) uint64 {
        if numGC == 0 {
                return 0
        }
        return pauseTotalNs / uint64(numGC) / 1000000
}

// ── Goroutine 2: Traffic Sensor ──
// v5.0: เพิ่ม Top Talkers + Protocol Distribution
func trafficCollector(ch chan<- TrafficData) {
        var totalPkts int64
        tick := 0
        for {
                now := time.Now().Unix()
                data, err := readTrafficFromSystem()
                if err != nil {
                        // Simulate realistic traffic with natural variation
                        variation := int64(200 * float64(tick%60) / 60.0)
                        data = TrafficData{
                                RxPktsPerSec:  1000 + (now%500) + variation,
                                TxPktsPerSec:  800 + (now%300) + variation/2,
                                ActiveConns:   50 + (now % 20),
                                RxBytesPerSec: float64(1200000 + (now%600000) + variation*1000),
                                TxBytesPerSec: float64(800000 + (now%400000) + variation*500),
                        }
                }

                // v5.0: Simulate Top Talkers (real data would come from packet capture)
                data.TopTalkers = simulateTopTalkers(now)
                data.Protocols = []ProtocolEntry{
                        {Name: "TCP",  Count: data.RxPktsPerSec*70/100 + data.TxPktsPerSec*70/100},
                        {Name: "UDP",  Count: data.RxPktsPerSec*20/100 + data.TxPktsPerSec*20/100},
                        {Name: "ICMP", Count: data.RxPktsPerSec*5/100 + data.TxPktsPerSec*5/100},
                        {Name: "Other",Count: data.RxPktsPerSec*5/100 + data.TxPktsPerSec*5/100},
                }
                data.TCPCount = data.Protocols[0].Count
                data.UDPCount = data.Protocols[1].Count
                data.ICMPCount = data.Protocols[2].Count

                totalPkts += data.RxPktsPerSec + data.TxPktsPerSec
                data.TotalPkts = totalPkts
                ch <- data
                tick++
                time.Sleep(1 * time.Second)
        }
}

// simulateTopTalkers — generate realistic top talker data
func simulateTopTalkers(now int64) []TopTalkerEntry {
        return []TopTalkerEntry{
                {IP: "192.168.1.100", RxBytes: 5000000 + (now%1000000), TxBytes: 2000000 + (now%500000), Total: 7000000 + (now%1500000)},
                {IP: "10.0.0.55",     RxBytes: 3000000 + (now%800000),  TxBytes: 1500000 + (now%300000), Total: 4500000 + (now%1100000)},
                {IP: "172.16.0.22",   RxBytes: 2000000 + (now%500000),  TxBytes: 1000000 + (now%200000), Total: 3000000 + (now%700000)},
                {IP: "192.168.1.1",   RxBytes: 1000000 + (now%300000),  TxBytes: 800000 + (now%100000),   Total: 1800000 + (now%400000)},
                {IP: "10.10.10.10",   RxBytes: 500000 + (now%200000),   TxBytes: 300000 + (now%50000),    Total: 800000 + (now%250000)},
        }
}

// ── Goroutine 3: Threat Map Collector + Raw Stream ──
// v5.0: เพิ่ม raw event stream (real-time packet sniffing display)
func threatCollector(ch chan<- ThreatData) {
        for {
                ch <- parseThreatMap()
                time.Sleep(5 * time.Second)
        }
}

// ── readTrafficFromSystem ──
// TODO: รองรับ real traffic จาก Windows performance counters หรือ Bridge IPC
func readTrafficFromSystem() (TrafficData, error) {
        return TrafficData{}, fmt.Errorf("no real traffic data yet — using simulation")
}

// ── parseThreatMap ──
// v5.0: เพิ่ม raw stream entries from anomalous.json
func parseThreatMap() ThreatData {
        msg := ThreatData{
                ThreatMap: make(map[string]int),
                RawStream: make([]StreamEntry, 0, rawStreamSize),
        }

        paths := []string{
                "logs/anomalous.json",
                "../logs/anomalous.json",
                "../../logs/anomalous.json",
        }

        var file *os.File
        for _, p := range paths {
                f, err := os.Open(p)
                if err == nil {
                        file = f
                        break
                }
        }
        if file == nil {
                return msg
        }
        defer file.Close()

        scanner := bufio.NewScanner(file)
        var allEntries []StreamEntry
        for scanner.Scan() {
                var entry map[string]interface{}
                if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
                        continue
                }
                msg.TotalEvents++

                if attack, ok := entry["attack_type"].(string); ok {
                        msg.ThreatMap[attack]++
                        msg.LastAttack = attack
                        msg.LastAttackTime = time.Now()
                }
                if category, ok := entry["category"].(string); ok {
                        if _, exists := msg.ThreatMap[category]; !exists {
                                msg.ThreatMap[category] = 1
                        }
                }

                // v5.0: Build raw stream entry
                streamEntry := StreamEntry{
                        Timestamp: getStrField(entry, "timestamp", time.Now().Format("15:04:05")),
                        Source:    getStrField(entry, "source_ip", getStrField(entry, "src_ip", "unknown")),
                        EventType: getStrField(entry, "attack_type", getStrField(entry, "category", "packet")),
                        Detail:    getStrField(entry, "policy", "Log"),
                }
                allEntries = append(allEntries, streamEntry)
        }

        // Keep last N entries for raw stream display (ring buffer behavior)
        startIdx := 0
        if len(allEntries) > rawStreamSize {
                startIdx = len(allEntries) - rawStreamSize
        }
        msg.RawStream = allEntries[startIdx:]

        msg.UniqueThreats = len(msg.ThreatMap)
        return msg
}

// getStrField — helper to extract string field from JSON map
func getStrField(entry map[string]interface{}, key string, fallback string) string {
        if val, ok := entry[key].(string); ok {
                return val
        }
        return fallback
}

// ── sortThreats ──
func sortThreats(threatMap map[string]int) []ThreatEntry {
        entries := make([]ThreatEntry, 0, len(threatMap))
        for k, v := range threatMap {
                entries = append(entries, ThreatEntry{Name: k, Count: v})
        }
        sort.Slice(entries, func(i, j int) bool {
                return entries[i].Count > entries[j].Count
        })
        return entries
}

// ── sortTopTalkers ──
// Sort top talkers by total bandwidth (descending)
func sortTopTalkers(talkers []TopTalkerEntry) []TopTalkerEntry {
        sorted := make([]TopTalkerEntry, len(talkers))
        copy(sorted, talkers)
        sort.Slice(sorted, func(i, j int) bool {
                return sorted[i].Total > sorted[j].Total
        })
        return sorted
}

// ── formatUptime ──
func formatUptime(secs int64) string {
        h := secs / 3600
        m := (secs % 3600) / 60
        s := secs % 60
        return fmt.Sprintf("%dh %dm %ds", h, m, s)
}

// ── formatBytes ──
func formatBytes(b float64) string {
        if b >= 1048576 {
                return fmt.Sprintf("%.1f MB/s", b/1048576)
        }
        if b >= 1024 {
                return fmt.Sprintf("%.1f KB/s", b/1024)
        }
        return fmt.Sprintf("%.0f B/s", b)
}

// ── formatBytesTotal ──
// Format total bytes (not per-second)
func formatBytesTotal(b int64) string {
        if b >= 1073741824 {
                return fmt.Sprintf("%.1f GB", float64(b)/1073741824)
        }
        if b >= 1048576 {
                return fmt.Sprintf("%.1f MB", float64(b)/1048576)
        }
        if b >= 1024 {
                return fmt.Sprintf("%.1f KB", float64(b)/1024)
        }
        return fmt.Sprintf("%d B", b)
}

// ── formatComma ──
func formatComma(n int64) string {
        s := fmt.Sprintf("%d", n)
        if len(s) <= 3 {
                return s
        }
        var result string
        for i, c := range s {
                if i > 0 && (len(s)-i)%3 == 0 {
                        result += ","
                }
                result += string(c)
        }
        return result
}

// ── sparkline ──
func sparkline(values []int64) string {
        if len(values) == 0 {
                return ""
        }

        var max int64 = 1
        for _, v := range values {
                if v > max {
                        max = v
                }
        }

        blocks := []rune{'▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}
        var result string
        for _, v := range values {
                idx := int(float64(v) / float64(max) * float64(len(blocks)-1))
                if idx < 0 {
                        idx = 0
                }
                if idx >= len(blocks) {
                        idx = len(blocks) - 1
                }
                result += string(blocks[idx])
        }
        return result
}

// ── renderBar ──
func renderBar(value, maxValue, maxWidth int) string {
        if maxValue == 0 {
                maxValue = 1
        }
        filled := int(float64(value) / float64(maxValue) * float64(maxWidth))
        if filled > maxWidth {
                filled = maxWidth
        }
        empty := maxWidth - filled

        bar := ""
        for i := 0; i < filled; i++ {
                bar += "█"
        }
        for i := 0; i < empty; i++ {
                bar += "░"
        }
        return bar
}

// ── getDEFCON ──
func getDEFCON(threats ThreatData) int {
        if threats.TotalEvents == 0 {
                return 5
        }
        if threats.UniqueThreats >= 7 || threats.TotalEvents > 500 {
                return 1
        }
        if threats.UniqueThreats >= 5 || threats.TotalEvents > 200 {
                return 2
        }
        if threats.UniqueThreats >= 3 || threats.TotalEvents > 50 {
                return 3
        }
        if threats.UniqueThreats >= 1 || threats.TotalEvents > 10 {
                return 4
        }
        return 5
}

// ── getAlertLevel ──
func getAlertLevel(defcon int) string {
        switch defcon {
        case 1:
                return "CRITICAL"
        case 2:
                return "SEVERE"
        case 3:
                return "HIGH"
        case 4:
                return "ELEVATED"
        default:
                return "ALL CLEAR"
        }
}
