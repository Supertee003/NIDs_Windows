package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// GO-LOOPBACK-031: the aggregator REST API must stay loopback-only.
// The documented contract is 127.0.0.1:9200 and every in-tree client uses
// loopback; a bare ":port" bind would expose alerts + purge to the LAN.
func TestAPIAddrIsLoopbackOnly(t *testing.T) {
	addr := apiAddr(9200)
	if addr != "127.0.0.1:9200" {
		t.Errorf("apiAddr(9200) = %q, want %q", addr, "127.0.0.1:9200")
	}
	if strings.HasPrefix(addr, ":") {
		t.Errorf("apiAddr must never be a wildcard bind, got %q", addr)
	}
	if strings.Contains(addr, "0.0.0.0") {
		t.Errorf("apiAddr must never bind all interfaces, got %q", addr)
	}
}

func TestAPIAddrRespectsPort(t *testing.T) {
	if got := apiAddr(9300); got != "127.0.0.1:9300" {
		t.Errorf("apiAddr(9300) = %q, want %q", got, "127.0.0.1:9300")
	}
}

// DEADCODE-QUARANTINE: the aggregator's health counters used to be
// hardcoded zeros — a supervisor could not see ingest dying. The collector
// must report what it really did: lines parsed (in_events), parse failures
// (errors), and the wall-clock timestamp of the last successful ingest
// (last_event_ms; 0 = none yet).
func TestCollectorStatsMoveWithIngest(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "aegis_core.ndjson")
	content := `{"ts_ms":1000,"mono_ns":1,"level":"warning","event":"signature_match","rule":"R1","src_ip":"10.0.0.1"}
{"ts_ms":2000,"mono_ns":2,"level":"critical","event":"signature_match","rule":"R2","src_ip":"10.0.0.2"}
not-json-at-all
`
	if err := os.WriteFile(logPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	c := &Collector{filePath: logPath, aggregator: NewAlertAggregator(100)}
	c.readNewLines()

	ingested, parseErrors, lastIngestMs := c.Stats()
	if ingested != 2 {
		t.Fatalf("in_events: want 2 parsed lines, got %d", ingested)
	}
	if parseErrors != 1 {
		t.Fatalf("errors: want 1 parse failure, got %d", parseErrors)
	}
	if lastIngestMs <= 0 {
		t.Fatalf("last ingest must record a real time, got %d", lastIngestMs)
	}
	if got := c.aggregator.Count(); got != 2 {
		t.Fatalf("aggregator must have received both alerts, got %d", got)
	}
}

func TestHealthReportsCollectorStats(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "aegis_core.ndjson")
	line := `{"ts_ms":1000,"mono_ns":1,"level":"warning","event":"signature_match","rule":"R1","src_ip":"10.0.0.1"}` + "\n"
	if err := os.WriteFile(logPath, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	c := &Collector{filePath: logPath, aggregator: NewAlertAggregator(100)}
	c.readNewLines()

	srv := &Server{aggregator: c.aggregator, collector: c, startTime: time.Now()}
	req := httptest.NewRequest("GET", "/api/health", nil)
	rec := httptest.NewRecorder()
	srv.handleHealth(rec, req)

	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("health must be JSON: %v", err)
	}
	counters, ok := body["counters"].(map[string]interface{})
	if !ok {
		t.Fatalf("counters must be an object, got %T", body["counters"])
	}
	if counters["in_events"] != float64(1) {
		t.Fatalf("in_events: want 1, got %v", counters["in_events"])
	}
	if counters["errors"] != float64(0) {
		t.Fatalf("errors: want 0, got %v", counters["errors"])
	}
	age, ok := body["last_event_ms"].(float64)
	if !ok || age < 0 || age > 60000 {
		t.Fatalf("last_event_ms must be a real age, got %v", body["last_event_ms"])
	}
}

func TestHealthReportsHonestZeroBeforeAnyIngest(t *testing.T) {
	srv := &Server{
		aggregator: NewAlertAggregator(10),
		collector:  &Collector{aggregator: NewAlertAggregator(10)},
		startTime:  time.Now(),
	}
	req := httptest.NewRequest("GET", "/api/health", nil)
	rec := httptest.NewRecorder()
	srv.handleHealth(rec, req)

	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("health must be JSON: %v", err)
	}
	if body["last_event_ms"] != float64(0) {
		t.Fatalf("no ingest yet must age 0 (honest never), got %v", body["last_event_ms"])
	}
}
