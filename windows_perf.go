package main

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// =====================================================================
// AEGIS NOSE (Go) — Performance & Threat Counter Monitor
// ---------------------------------------------------------------------
// แก้จากเดิม: เดิมใช้ rand.Intn() (fake data) เปลี่ยนเป็นอ่าน stats จริง
//   - อ่าน log file `logs/anomalous.json` เพื่อนับ threat ที่ตรวจพบ
//   - แยกตาม layer (L4/L7/KERNEL_FILE/...) และ policy (BLOCK/ALERT)
//   - แสดง memory stats ของตัว Go process เอง
// =====================================================================

const (
	logFile   = "logs/anomalous.json"
	rateWinMs = 1000 // 1 วินาทีต่อ sample
)

// global counters
var (
	totalAlerts uint64
	totalBlocks uint64
	lastAlerts  uint64
	lastBlocks  uint64
)

type logEntry struct {
	Timestamp  string `json:"timestamp"`
	AttackType string `json:"attack_type"`
	Policy     string `json:"policy"`
	Layer      string `json:"layer"`
	RuleID     string `json:"rule_id"`
	Source     string `json:"source"`
}

func clearScreen() {
	fmt.Print("\033[H\033[2J")
}

// scanLogFile: อ่าน log ทั้งไฟล์ นับจำนวน alert/block และ break-down ตาม layer
func scanLogFile() (alerts uint64, blocks uint64, byLayer map[string]int) {
	byLayer = map[string]int{}
	data, err := os.ReadFile(logFile)
	if err != nil {
		return 0, 0, byLayer
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e logEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue
		}
		alerts++
		policy := strings.ToUpper(e.Policy)
		if policy == "BLOCK" || policy == "DROP" {
			blocks++
		}
		layer := e.Layer
		if layer == "" {
			layer = "UNKNOWN"
		}
		byLayer[layer]++
	}
	return alerts, blocks, byLayer
}

// readProcNetDev: อ่านจำนวน bytes rx/tx จาก /proc/net/dev บน Linux เท่านั้น
// บน Windows จะ return 0,0 (ไม่มี /proc) — ใช้ GetIfTable API ในอนาคต
func readProcNetDev() (rxBytes, txBytes uint64) {
	// NOTE: บน Windows ไม่มี /proc/net/dev — นี่เป็น placeholder สำหรับ cross-platform
	// TODO: ใช้ GetIfTable2 / GetIfEntry API ของ Windows เพื่ออ่าน real interface stats
	return 0, 0
}

func formatRate(n uint64, elapsed time.Duration) string {
	if elapsed <= 0 {
		return "0"
	}
	perSec := float64(n) / elapsed.Seconds()
	return strconv.FormatFloat(perSec, 'f', 1, 64)
}

func main() {
	fmt.Println("[*] AEGIS NOSE starting — reading stats from", logFile)

	// ตรวจสอบว่า log dir มีอยู่
	if _, err := os.Stat("logs"); os.IsNotExist(err) {
		_ = os.Mkdir("logs", 0755)
	}

	ticker := time.NewTicker(rateWinMs * time.Millisecond)
	defer ticker.Stop()

	var lastSampleTime = time.Now()
	var lastRx, lastTx uint64 = 0, 0
	lastRx, lastTx = readProcNetDev()

	for range ticker.C {
		now := time.Now()
		elapsed := now.Sub(lastSampleTime)
		lastSampleTime = now

		alerts, blocks, byLayer := scanLogFile()

		// delta ตั้งแต่ sample ก่อน
		alertsDelta := alerts - lastAlerts
		blocksDelta := blocks - lastBlocks
		lastAlerts = alerts
		lastBlocks = blocks
		atomic.AddUint64(&totalAlerts, alertsDelta)
		atomic.AddUint64(&totalBlocks, blocksDelta)

		rxNow, txNow := readProcNetDev()
		rxDelta := rxNow - lastRx
		txDelta := txNow - lastTx
		lastRx, lastTx = rxNow, txNow

		clearScreen()

		var m runtime.MemStats
		runtime.ReadMemStats(&m)

		fmt.Println("\033[36;1m=====================================================\033[0m")
		fmt.Println("\033[36;1m           AEGIS NOSE (GO) - PERF MONITOR           \033[0m")
		fmt.Println("\033[36;1m=====================================================\033[0m")
		fmt.Printf("\033[33m[ SYSTEM RESOURCE ]\033[0m\n")
		fmt.Printf(" Alloc Memory : %v MiB\n", m.Alloc/1024/1024)
		fmt.Printf(" Total Alloc  : %v MiB\n", m.TotalAlloc/1024/1024)
		fmt.Printf(" Sys Memory   : %v MiB\n", m.Sys/1024/1024)
		fmt.Printf(" Num GC       : %v\n", m.NumGC)
		fmt.Println("-----------------------------------------------------")
		fmt.Printf("\033[32m[ THREAT STATS (from logs/anomalous.json) ]\033[0m\n")
		fmt.Printf(" Total Alerts : %d   (rate: %s/s)\n", alerts, formatRate(alertsDelta, elapsed))
		fmt.Printf(" Total Blocks : %d   (rate: %s/s)\n", blocks, formatRate(blocksDelta, elapsed))
		fmt.Println("-----------------------------------------------------")
		fmt.Printf("\033[35m[ BREAKDOWN BY LAYER ]\033[0m\n")
		if len(byLayer) == 0 {
			fmt.Println("  (no threats yet)")
		}
		for layer, count := range byLayer {
			fmt.Printf("  %-15s : %d\n", layer, count)
		}
		fmt.Println("-----------------------------------------------------")
		fmt.Printf("\033[36m[ NETWORK (placeholder) ]\033[0m\n")
		fmt.Printf(" RX delta : %d bytes   TX delta : %d bytes\n", rxDelta, txDelta)
		fmt.Println("\033[36;1m=====================================================\033[0m")
		fmt.Println(" Status: \033[32m[ MONITORING ]\033[0m - Press Ctrl+C to exit")
	}
}
