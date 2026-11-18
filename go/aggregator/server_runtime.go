package main

// server_runtime.go — build-tag-neutral aggregator runtime shared by both
// entrypoints: the console main() (main.go, tag `!service`) and the Windows
// service wrapper (service_main.go, tag `service`).
//
//   - runAggregator(): full startup sequence (collector + correlator + REST).
//     Non-fatal errors are logged, never log.Fatalf, so the service variant
//     can still report Running / Stopped cleanly to the SCM.
//   - requestShutdown(): graceful-stop used by the service wrapper on SCM
//     Stop/Shutdown and by the console path after SIGINT/SIGTERM.
import (
	"log"
	"net/http"
	"path/filepath"
	"time"
)

// shared shutdown handles, set by whichever entrypoint started the server.
var shutdownServer *http.Server
var shutdownCollector *Collector

// requestShutdown triggers the graceful-stop path. No-op if the server
// never started.
func requestShutdown() {
	if shutdownCollector != nil {
		shutdownCollector.Stop()
	}
	if shutdownServer != nil {
		_ = shutdownServer.Close()
	}
}

// runAggregator executes the full startup sequence. In the service variant
// this must not os.Exit: the wrapper tracks server liveness and reports
// Stopped to the SCM when this returns.
func runAggregator() {
	startTime := time.Now()
	logPath := getEnv("AEGIS_LOG_PATH", DEFAULT_LOG_PATH)
	apiPort := getEnvInt("AEGIS_API_PORT", DEFAULT_API_PORT)
	maxAlerts := getEnvInt("AEGIS_MAX_ALERTS", DEFAULT_MAX_ALERTS)

	absLogPath, err := filepath.Abs(logPath)
	if err != nil {
		log.Printf("[AGGREGATOR] log path resolve failed: %v", err)
		return
	}
	log.Printf("[AGGREGATOR] log file: %s", absLogPath)
	log.Printf("[AGGREGATOR] API port: %d, max alerts: %d", apiPort, maxAlerts)

	aggregator := NewAlertAggregator(maxAlerts)
	correlator := NewCorrelator(24 * time.Hour)

	collector, err := NewCollector(absLogPath, aggregator)
	if err != nil {
		log.Printf("[AGGREGATOR] collector create failed: %v", err)
		return
	}
	if err := collector.Start(); err != nil {
		log.Printf("[AGGREGATOR] collector start failed: %v", err)
		return
	}

	server := &Server{aggregator: aggregator, collector: collector,
		correlator: correlator, startTime: startTime}
	go server.correlateAlerts()
	go server.purgeLoop()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/alerts", server.handleAlerts)
	mux.HandleFunc("/api/alerts/critical", server.handleCriticalAlerts)
	mux.HandleFunc("/api/alerts/", server.handleAlertByHash)
	mux.HandleFunc("/api/sessions", server.handleSessions)
	mux.HandleFunc("/api/sessions/", server.handleSessionByID)
	mux.HandleFunc("/api/stats", server.handleStats)
	mux.HandleFunc("/api/health", server.handleHealth)
	mux.HandleFunc("/api/purge", server.handlePurge)
	mux.HandleFunc("/", server.handleRoot)

	server.httpServer = &http.Server{Addr: apiAddr(apiPort), Handler: mux}
	shutdownServer = server.httpServer
	shutdownCollector = collector

	log.Printf("[AGGREGATOR] REST API available at %s", apiAddr(apiPort))
	if err := server.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("[AGGREGATOR] HTTP server error: %v", err)
	}
}
