// ============================================================
// main.go - AEGIS NIDS Alert Aggregator Service (Phase 18)
// ============================================================
// High-performance alert aggregator that:
//   1. Watches logs/aegis_core.ndjson for new alerts
//   2. Deduplicates by rule+IP+event hash
//   3. Correlates events across tiers using session_id
//   4. Exposes REST API on :9200 for dashboard/CLI queries
//
// Endpoints:
//   GET  /api/alerts          - List all alerts
//   GET  /api/alerts/critical - List only critical alerts
//   GET  /api/alerts/{hash}   - Get specific alert by hash
//   GET  /api/sessions         - List top sessions
//   GET  /api/sessions/{id}    - Get session timeline
//   GET  /api/stats            - Aggregator statistics
//   GET  /api/health           - Health check
//   POST /api/purge             - Purge old alerts (body: {"max_age_hours": 24})

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/google/uuid"
)

const (
	DEFAULT_LOG_PATH    = "logs/aegis_core.ndjson"
	DEFAULT_API_PORT    = 9200
	DEFAULT_MAX_ALERTS  = 10000
	DEFAULT_MAX_AGE_HRS = 24
)

// Server holds all components
type Server struct {
	aggregator *AlertAggregator
	collector  *Collector
	correlator *Correlator
	httpServer *http.Server
}

func main() {
	// Get config from env or defaults
	logPath := getEnv("AEGIS_LOG_PATH", DEFAULT_LOG_PATH)
	apiPort := getEnvInt("AEGIS_API_PORT", DEFAULT_API_PORT)
	maxAlerts := getEnvInt("AEGIS_MAX_ALERTS", DEFAULT_MAX_ALERTS)

	// Resolve absolute path
	absLogPath, err := filepath.Abs(logPath)
	if err != nil {
		log.Fatalf("Failed to resolve log path: %v", err)
	}

	log.Printf("[AGGREGATOR] AEGIS NIDS Alert Aggregator starting")
	log.Printf("[AGGREGATOR] Log file: %s", absLogPath)
	log.Printf("[AGGREGATOR] API port: %d", apiPort)
	log.Printf("[AGGREGATOR] Max alerts: %d", maxAlerts)

	// Initialize components
	aggregator := NewAlertAggregator(maxAlerts)
	correlator := NewCorrelator(24 * time.Hour)

	collector, err := NewCollector(absLogPath, aggregator)
	if err != nil {
		log.Fatalf("Failed to create collector: %v", err)
	}

	if err := collector.Start(); err != nil {
		log.Fatalf("Failed to start collector: %v", err)
	}

	// Create server
	server := &Server{
		aggregator: aggregator,
		collector:  collector,
		correlator: correlator,
	}

	// Start correlator that watches for new alerts
	go server.correlateAlerts()

	// Start purge goroutine (every 5 min)
	go server.purgeLoop()

	// Setup HTTP server
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

	server.httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", apiPort),
		Handler: mux,
	}

	// Start HTTP server
	go func() {
		log.Printf("[AGGREGATOR] REST API available at http://localhost:%d", apiPort)
		if err := server.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Printf("[AGGREGATOR] Shutting down...")
	collector.Stop()
	server.httpServer.Close()
	log.Printf("[AGGREGATOR] Shutdown complete")
}

// correlateAlerts feeds alerts to the correlator
func (s *Server) correlateAlerts() {
	// Poll aggregator for new alerts and feed to correlator
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	seen := make(map[string]bool)

	for range ticker.C {
		alerts := s.aggregator.GetAll()
		for _, a := range alerts {
			if !seen[a.Hash] {
				seen[a.Hash] = true
				s.correlator.AddEvent(a)
			}
		}
	}
}

// purgeLoop periodically purges old alerts and sessions
func (s *Server) purgeLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		purgedAlerts := s.aggregator.PurgeOlder(DEFAULT_MAX_AGE_HRS * time.Hour)
		purgedSessions := s.correlator.PurgeOlder()
		if purgedAlerts > 0 || purgedSessions > 0 {
			log.Printf("[AGGREGATOR] Purged %d alerts, %d sessions", purgedAlerts, purgedSessions)
		}
	}
}

// HTTP Handlers

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<html><body>
<h1>AEGIS NIDS Alert Aggregator</h1>
<ul>
<li><a href="/api/alerts">/api/alerts</a> - All alerts</li>
<li><a href="/api/alerts/critical">/api/alerts/critical</a> - Critical alerts only</li>
<li><a href="/api/sessions">/api/sessions</a> - Top sessions</li>
<li><a href="/api/stats">/api/stats</a> - Statistics</li>
<li><a href="/api/health">/api/health</a> - Health check</li>
</ul>
</body></html>`)
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	alerts := s.aggregator.GetAll()
	writeJSON(w, alerts)
}

func (s *Server) handleCriticalAlerts(w http.ResponseWriter, r *http.Request) {
	alerts := s.aggregator.GetCritical()
	writeJSON(w, alerts)
}

func (s *Server) handleAlertByHash(w http.ResponseWriter, r *http.Request) {
	hash := r.URL.Path[len("/api/alerts/"):]
	if hash == "" {
		http.Error(w, "Hash required", http.StatusBadRequest)
		return
	}
	alert := s.aggregator.GetByHash(hash)
	if alert == nil {
		http.Error(w, "Alert not found", http.StatusNotFound)
		return
	}
	writeJSON(w, alert)
}

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	sessions := s.correlator.GetTopSessions(20)
	writeJSON(w, sessions)
}

func (s *Server) handleSessionByID(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Path[len("/api/sessions/"):]
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid session ID", http.StatusBadRequest)
		return
	}
	timeline := s.correlator.FormatTimeline(id)
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, timeline)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	stats := map[string]interface{}{
		"total_alerts":   s.aggregator.Count(),
		"total_sessions": s.correlator.GetSessionCount(),
		"timestamp":      time.Now().Unix(),
	}
	writeJSON(w, stats)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"healthy","timestamp":%d}`, time.Now().Unix())
}

func (s *Server) handlePurge(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		MaxAgeHours int `json:"max_age_hours"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.MaxAgeHours == 0 {
		req.MaxAgeHours = DEFAULT_MAX_AGE_HRS
	}

	purged := s.aggregator.PurgeOlder(time.Duration(req.MaxAgeHours) * time.Hour)
	writeJSON(w, map[string]int{"purged": purged})
}

// generateUUID creates a new UUID string
func generateUUID() string {
	return uuid.New().String()
}

// writeJSON writes a JSON response
func writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, "Failed to encode JSON", http.StatusInternalServerError)
	}
}

// getEnv gets env var or returns default
func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

// getEnvInt gets env var as int or returns default
func getEnvInt(key string, defaultVal int) int {
	if val := os.Getenv(key); val != "" {
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return defaultVal
}
