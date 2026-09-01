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
        "flag"
        "encoding/json"

        tea "github.com/charmbracelet/bubbletea"
)

// AEGIS_NOSE_VERSION is the SEMVER reported by `aegis-nose --version`.
// Parsed by tests/runtime/test_version.py.
const AEGIS_NOSE_VERSION = "5.0.0"

func main() {
        // G27 Gate-A: --version flag. Print SEMVER + exit 0 before any
        // flag.Parse() so it works even if other flags are malformed.
        for _, arg := range os.Args[1:] {
                if arg == "--version" || arg == "-v" || arg == "-V" {
                        fmt.Printf("aegis-nose %s\n", AEGIS_NOSE_VERSION)
                        os.Exit(0)
                }
        }

        // Parse command line flags
        headless := flag.Bool("headless", false, "Run in headless mode (no TUI, output JSON to stdout)")
        flag.Parse()

        // Create buffered channels for collector data
        resourceCh := make(chan ResourceData, 4)
        trafficCh := make(chan TrafficData, 4)
        threatCh := make(chan ThreatData, 4)

        // Record start time
        startTime := time.Now()

        // Launch 3 collector goroutines
        go resourceCollector(resourceCh, startTime)
        go trafficCollector(trafficCh)
        go threatCollector(threatCh)

        if *headless {
                // HEADLESS MODE: Continuously print JSON metrics to stdout
                fmt.Fprintf(os.Stderr, "[AEGIS NOSE] Running in Headless Mode (JSON to stdout)...\n")
                
                ticker := time.NewTicker(2 * time.Second)
                defer ticker.Stop()
                
                for range ticker.C {
                        var resData ResourceData
                        var trafData TrafficData
                        var thrData ThreatData
                        
                        // Non-blocking read from channels
                        select { case resData = <-resourceCh: default: }
                        select { case trafData = <-trafficCh: default: }
                        select { case thrData = <-threatCh: default: }

                        // Construct unified JSON state
                        state := map[string]interface{}{
                                "timestamp": time.Now().Format(time.RFC3339),
                                "resource": resData,
                                "traffic": trafData,
                                "threat": thrData,
                        }
                        
                        jsonBytes, err := json.Marshal(state)
                        if err == nil {
                                fmt.Println(string(jsonBytes))
                        }
                }
        } else {
                // TUI MODE: Run bubbletea program
                p := tea.NewProgram(
                        initialModel(resourceCh, trafficCh, threatCh, startTime),
                        tea.WithMouseCellMotion(),
                )

                if _, err := p.Run(); err != nil {
                        fmt.Fprintf(os.Stderr, "[AEGIS NOSE] Error: %v\n", err)
                        os.Exit(1)
                }
        }
}
