package main

// =====================================================================
// main.go — AEGIS NOSE (Go) v5.0 Entry Point
// =====================================================================
//  TUI Dashboard สำหรับ "จมูกดมกลิ่นหาความผิดปกติ"
//  เน้น: Sniffing, Traffic, Health — Cool-tone analytics dashboard
//  ใช้ bubbletea + lipgloss แทน raw ANSI codes
//
//  Architecture:
//    3 Goroutine Collectors → Channels → bubbletea Model → TUI Render
//    + JSON to stderr (for Bridge/Brain consumption)
//
//  Launch:  cd nose && go run .
//           (หรือ go build -o ../dist/aegis-nose.exe . && ..\dist\aegis-nose.exe)
// =====================================================================

import (
        "fmt"
        "os"
        "time"

        tea "github.com/charmbracelet/bubbletea"
)

func main() {
        // Create buffered channels for collector data
        resourceCh := make(chan ResourceData, 4)
        trafficCh := make(chan TrafficData, 4)
        threatCh := make(chan ThreatData, 4)

        // Record start time
        startTime := time.Now()

        // Launch 3 collector goroutines
        // (each runs independently, writing to its channel at its own interval)
        go resourceCollector(resourceCh, startTime)
        go trafficCollector(trafficCh)
        go threatCollector(threatCh)

        // Create bubbletea program
        p := tea.NewProgram(
                initialModel(resourceCh, trafficCh, threatCh, startTime),
                // NOTE: Do NOT use tea.WithAltScreen() — รันใน cmd /k window
                //       alt screen อาจทำให้หน้าต่าง minimized ไม่แสดงเนื้อหา
                tea.WithMouseCellMotion(),
        )

        // Run the TUI (blocks until quit)
        if _, err := p.Run(); err != nil {
                fmt.Fprintf(os.Stderr, "[AEGIS NOSE] Error: %v\n", err)
                os.Exit(1)
        }
}
