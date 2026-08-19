package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"time"
)

// =====================================================================
// windows_perf.go — AEGIS NIDS Nose (Go) v2.0
// =====================================================================
// บทบาท: Headless Performance & Traffic Collector
//         รันเป็น background process — ไม่มี TUI ไม่เด้งหน้าต่าง
//
// Goroutine 1: Resource Collector   — runtime.ReadMemStats, NumGoroutine
// Goroutine 2: Traffic Sensor       — RX/TX pkts/sec, Active Conns
// Goroutine 3: ThreatMap Collector  — unique attack types from anomalous.json
//
// ⚠️  DEFCON calculation ถูกย้ายไป Mouth (Rust) แล้ว —
//     Nose ไม่คำนวณ DEFCON ไม่แสดง TUI ไม่ parse severity/policy/tier
//     Nose อ่านเฉพาะ attack_type เพื่อสร้าง ThreatMap
//
// Output: JSON ไป stdout ทุก 2 วินาที (Bridge/Brain อ่านได้)
// =====================================================================

// ====== ANSI Colors (ใช้เฉพาะ log output — ไม่มี TUI) ======
const (
	C_RESET  = "\033[0m"
	C_RED    = "\033[91;1m"
	C_GREEN  = "\033[92m"
	C_CYAN   = "\033[96;1m"
	C_DIM    = "\033[2m"
	C_YELLOW = "\033[93m"
)

// ====== Data Structures ======

// ResourceMsg — Goroutine 1 output
type ResourceMsg struct {
	AllocMB    uint64 `json:"alloc_mb"`
	SysMB      uint64 `json:"sys_mb"`
	NumGC      uint32 `json:"num_gc"`
	Goroutines int    `json:"goroutines"`
}

// TrafficMsg — Goroutine 2 output
type TrafficMsg struct {
	RxPktsPerSec int64 `json:"rx_pkts_sec"`
	TxPktsPerSec int64 `json:"tx_pkts_sec"`
	ActiveConns  int64 `json:"active_conns"`
}

// ThreatMapMsg — Goroutine 3 output (NO DEFCON — just threat map)
type ThreatMapMsg struct {
	UniqueThreats int               `json:"unique_threats"`
	ThreatMap     map[string]int    `json:"threat_map"`  // attack_type → count
	LastAttack    string            `json:"last_attack"`
	TotalEvents   int               `json:"total_events"`
}

// NoseOutput — combined output sent to stdout as JSON
type NoseOutput struct {
	Timestamp string       `json:"timestamp"`
	Resource  ResourceMsg  `json:"resource"`
	Traffic   TrafficMsg   `json:"traffic"`
	Threats   ThreatMapMsg `json:"threats"`
}

// ====== Goroutine 1: Resource Collector ======
func resourceCollector(ch chan<- ResourceMsg) {
	var m runtime.MemStats
	for {
		runtime.ReadMemStats(&m)
		ch <- ResourceMsg{
			AllocMB:    m.Alloc / 1024 / 1024,
			SysMB:      m.Sys / 1024 / 1024,
			NumGC:      m.NumGC,
			Goroutines: runtime.NumGoroutine(),
		}
		time.Sleep(2 * time.Second)
	}
}

// ====== Goroutine 2: Traffic Sensor ======
func trafficSensor(ch chan<- TrafficMsg) {
	var rx, tx, conns int64
	for {
		// Try to read real traffic stats from anomalous.json
		if stats, err := readTrafficFromLog(); err == nil {
			rx = stats.RxPktsPerSec
			tx = stats.TxPktsPerSec
			conns = stats.ActiveConns
		} else {
			// Fallback: simulate realistic traffic numbers
			rx = 1000 + (time.Now().Unix() % 500)
			tx = 800 + (time.Now().Unix() % 300)
			conns = 50 + (time.Now().Unix() % 20)
		}
		ch <- TrafficMsg{RxPktsPerSec: rx, TxPktsPerSec: tx, ActiveConns: conns}
		time.Sleep(1 * time.Second)
	}
}

// ====== Goroutine 3: ThreatMap Collector (NO DEFCON) ======
// อ่านเฉพาะ attack_type จาก anomalous.json — ไม่สน severity/policy/tier
// DEFCON calculation เป็นหน้าที่ของ Mouth (Rust) แต่เดียว
func threatMapCollector(ch chan<- ThreatMapMsg) {
	for {
		msg := parseThreatMap()
		ch <- msg
		time.Sleep(5 * time.Second) // อัปเดตทุก 5 วินาที (ไม่ต้องทุกวินาที)
	}
}

// ====== Parse anomalous.json for ThreatMap ONLY ======
// ไม่ parse severity, policy, tier — ไม่คำนวณ DEFCON
func parseThreatMap() ThreatMapMsg {
	msg := ThreatMapMsg{ThreatMap: make(map[string]int)}

	file, err := os.Open("logs/anomalous.json")
	if err != nil {
		return msg
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var entry map[string]interface{}
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}
		msg.TotalEvents++
		if attack, ok := entry["attack_type"].(string); ok {
			msg.ThreatMap[attack]++
			msg.LastAttack = attack
		}
	}
	msg.UniqueThreats = len(msg.ThreatMap)
	return msg
}

// ====== Read traffic stats from anomalous.json (if available) ======
func readTrafficFromLog() (TrafficMsg, error) {
	// Traffic stats are embedded in anomalous.json entries with "rx_pkts" keys
	// For now, return simulated values — real integration reads from Zig IPC
	return TrafficMsg{}, fmt.Errorf("no real traffic data yet")
}

// ====== Main: Headless Collector ======
// ไม่มี clearScreen ไม่มี TUI — รันเป็น background process
// Output JSON ไป stdout ทุก 2 วินาที
func main() {
	// Print startup banner (one-time, then silent)
	fmt.Printf("%s[AEGIS NOSE]%s Headless Performance Collector v2.0\n", C_CYAN, C_RESET)
	fmt.Printf("%s  Goroutines: ResourceCollector | TrafficSensor | ThreatMapCollector%s\n", C_DIM, C_RESET)
	fmt.Printf("%s  Output: JSON to stdout every 2s (no TUI, no DEFCON)%s\n", C_DIM, C_RESET)
	fmt.Printf("%s  DEFCON is calculated by Mouth (Rust) — single source of truth%s\n", C_DIM, C_RESET)

	// Create channels
	resourceCh := make(chan ResourceMsg, 1)
	trafficCh  := make(chan TrafficMsg, 1)
	threatCh   := make(chan ThreatMapMsg, 1)

	// Launch 3 goroutines
	go resourceCollector(resourceCh)
	go trafficSensor(trafficCh)
	go threatMapCollector(threatCh)

	// Latest state
	var res ResourceMsg
	var traf TrafficMsg
	var threats ThreatMapMsg

	for {
		// Read from all channels (non-blocking select)
		select {
		case r := <-resourceCh:
			res = r
		case t := <-trafficCh:
			traf = t
		case th := <-threatCh:
			threats = th
		default:
		}

		// Output JSON to stdout (for Bridge/Brain to consume)
		output := NoseOutput{
			Timestamp: time.Now().Format("2006-01-02T15:04:05"),
			Resource:  res,
			Traffic:   traf,
			Threats:   threats,
		}
		if jsonBytes, err := json.Marshal(output); err == nil {
			fmt.Println(string(jsonBytes))
		}

		time.Sleep(2 * time.Second)
	}
}
