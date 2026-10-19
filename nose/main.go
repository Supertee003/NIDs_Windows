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
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// AEGIS_NOSE_VERSION is the SEMVER reported by `aegis-nose --version`.
// Parsed by tests/runtime/test_version.py.
const AEGIS_NOSE_VERSION = "5.0.0"

// NOSE-HEALTH-190 (DEADCODE-QUARANTINE): headless beacon counters must move
// with real work — the old block hardcoded zeros, so a supervisor could not
// tell a live collector loop from a dead one. In headless mode nose's events
// are its collector samples: in_events counts samples consumed, out_events
// counts beacons emitted, last_event_ms is the age of the most recent sample
// (0 = none yet; >5x the health interval = soft failure, RUNTIME_CONTRACT
// §4.1). Capture-mode frame counters are reported daemon-side (nose_frames_*).
type headlessTelemetry struct {
	inEvents  uint64
	outEvents uint64
	lastEvent time.Time // zero = nothing processed yet
}

func (t *headlessTelemetry) noteSamples(n int, now time.Time) {
	if n == 0 {
		return
	}
	t.inEvents += uint64(n)
	t.lastEvent = now
}

// noteBeacon counts a beacon once it is on stdout; the payload of that
// beacon carries the pre-increment value (prior beacons only).
func (t *headlessTelemetry) noteBeacon() {
	t.outEvents++
}

func (t *headlessTelemetry) lastEventAgeMs(now time.Time) int64 {
	if t.lastEvent.IsZero() {
		return 0 // no event yet — honest "never", not a fake freshness
	}
	return now.Sub(t.lastEvent).Milliseconds()
}

// NOSE-JSON-166: headless beacon constructor (extracted for contract
// tests; behavior identical to the former inline literal).
func buildHeadlessState(resData ResourceData, trafData TrafficData, thrData ThreatData, tel *headlessTelemetry, startTime time.Time, pid int) map[string]interface{} {
	return map[string]interface{}{
		"op":            "HEALTH",
		"state":         "RUNNING",
		"status":        "OK",
		"component":     "nose",
		"version":       AEGIS_NOSE_VERSION,
		"pid":           pid,
		"uptime_ms":     time.Since(startTime).Milliseconds(),
		"last_event_ms": tel.lastEventAgeMs(time.Now()),
		"counters": map[string]interface{}{
			"in_events":  tel.inEvents,
			"out_events": tel.outEvents,
			"errors":     0, // no error path in the synthetic headless loop
			"dropped":    0, // no drop path in the synthetic headless loop
		},
		"deps": []map[string]string{
			{"name": "core", "state": "RUNNING"},
		},
		// Nose-specific metrics (kept for downstream consumers).
		"timestamp": time.Now().Format(time.RFC3339),
		"resource":  resData,
		"traffic":   trafData,
		"threat":    thrData,
	}
}

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
	capture := flag.Bool("capture", false, "Run packet capture (Go Nose) -> CanonicalEvent -> Zig pipe")
	captureProbe := flag.Bool("capture-probe", false, "Probe raw Npcap packets without BPF, CanonicalEvent, or pipe")
	listDevices := flag.Bool("list-devices", false, "List Npcap devices, descriptions, and addresses")
	captureProbeAll := flag.Bool("capture-probe-all", false, "Probe every Npcap device for raw packets")
	capturePipe := flag.String("pipe", nosePipeName, "Named pipe consumer (Zig core) for -capture")
	captureIface := flag.String("iface", "", "Exact Npcap interface name (empty = auto-select) for -capture")
	requireIface := flag.Bool("require-iface", false, "Refuse auto-selection; required for isolated VMware lab capture")
	liveTalkers := flag.Bool("live-talkers", false, "Feed Top Talkers from live Npcap capture (non-promiscuous, no pipe writes; falls back to synthetic silently)")
	selfTest := flag.Bool("capture-self-test", false, "Run capture encoder self-test then exit")
	injectObserve := flag.Bool("inject-observe", false, "Send canonical alert-only fixture through the Zig Nose pipe")
	injectCount := flag.Int("inject-count", 1, "Number of observe-only canonical fixtures to send")
	flag.Parse()

	if (*capture || *captureProbe) && *requireIface && *captureIface == "" {
		fmt.Fprintln(os.Stderr, "[AEGIS NOSE] REFUSE: --require-iface needs --iface <exact Npcap name>")
		fmt.Fprintln(os.Stderr, "[AEGIS NOSE] First run: aegis-nose.exe --list-devices")
		os.Exit(2)
	}

	if *selfTest {
		if err := captureSelfTest(); err != nil {
			fmt.Fprintf(os.Stderr, "[AEGIS NOSE] self-test failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *injectObserve {
		if err := runObserveInjection(*capturePipe, *injectCount); err != nil {
			fmt.Fprintf(os.Stderr, "[AEGIS NOSE] observe injection failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *captureProbe {
		if err := captureProbeRun(*captureIface, 15*time.Second); err != nil {
			fmt.Fprintf(os.Stderr, "[AEGIS NOSE] capture probe error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *listDevices {
		if err := printCaptureDevices(); err != nil {
			fmt.Fprintf(os.Stderr, "[AEGIS NOSE] device enumeration error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *captureProbeAll {
		if err := captureProbeAllRun(5 * time.Second); err != nil {
			fmt.Fprintf(os.Stderr, "[AEGIS NOSE] probe-all error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Create buffered channels for collector data
	resourceCh := make(chan ResourceData, 4)
	trafficCh := make(chan TrafficData, 4)
	threatCh := make(chan ThreatData, 4)

	// Record start time
	startTime := time.Now()

	// CAPTURE MODE: acquisition-only packet capture feeding the Zig core.
	if *capture {
		stop := make(chan struct{})
		go func() {
			if err := runCapture(*captureIface, *capturePipe, stop); err != nil {
				fmt.Fprintf(os.Stderr, "[AEGIS NOSE] capture error: %v\n", err)
				os.Exit(1)
			}
		}()
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt)
		<-sig
		close(stop)
		return
	}

	// Launch 3 collector goroutines
	go resourceCollector(resourceCh, startTime)
	go trafficCollector(trafficCh)
	go threatCollector(threatCh)

	// NOSE-TALK-145: opt-in live talkers feed. Any failure (no Npcap,
	// no permission) keeps today's synthetic path with one stderr note.
	if *liveTalkers {
		if err := startLiveTalkersFeed(); err != nil {
			fmt.Fprintf(os.Stderr, "[AEGIS NOSE] live talkers unavailable, synthetic retained: %v\n", err)
		}
	}

	if *headless {
		// HEADLESS MODE: Continuously print JSON metrics to stdout.
		// G35: each JSON beacon now includes a HEALTH envelope so the
		// supervisor and tests/runtime can probe nose lifecycle by
		// reading the last JSON line from stdout (per RUNTIME_CONTRACT
		// §4.1 — "stdout JSON line" transport).
		fmt.Fprintf(os.Stderr, "[AEGIS NOSE] Running in Headless Mode (JSON to stdout)...\n")

		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		// NOSE-HEALTH-190: count the samples this loop actually consumed.
		tel := &headlessTelemetry{}
		for range ticker.C {
			var resData ResourceData
			var trafData TrafficData
			var thrData ThreatData

			consumed := 0
			// Non-blocking read from channels
			select {
			case resData = <-resourceCh:
				consumed++
			default:
			}
			select {
			case trafData = <-trafficCh:
				consumed++
			default:
			}
			select {
			case thrData = <-threatCh:
				consumed++
			default:
			}
			tel.noteSamples(consumed, time.Now())

			// Construct unified JSON state with HEALTH envelope.
			// Schema fields required by RUNTIME_CONTRACT.md §4.1:
			//   component, state, pid, uptime_ms, last_event_ms,
			//   counters (in_events, out_events, errors, dropped), deps
			state := buildHeadlessState(resData, trafData, thrData, tel, startTime, os.Getpid())

			jsonBytes, err := json.Marshal(state)
			if err == nil {
				fmt.Println(string(jsonBytes))
				tel.noteBeacon()
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
