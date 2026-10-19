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

// ============================================================
// CI-GAPS (2026-10-19): REST handler pins. The HTTP surface had exactly
// one tested endpoint (/api/health, DEADCODE-QUARANTINE) even though the
// dashboard + operator CLI consume the rest. These pin the read paths and
// the purge contract with httptest only -- no listener, no state on disk.
// ============================================================

func newHandlerTestServer() *Server {
	return &Server{
		aggregator: NewAlertAggregator(100),
		correlator: NewCorrelator(24 * time.Hour),
		collector:  &Collector{aggregator: NewAlertAggregator(100)},
		startTime:  time.Now(),
	}
}

func TestRootListsTheAPISurface(t *testing.T) {
	srv := newHandlerTestServer()
	rec := httptest.NewRecorder()
	srv.handleRoot(rec, httptest.NewRequest("GET", "/", nil))

	if rec.Code != 200 {
		t.Fatalf("root must answer 200, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("root must be text/html, got %q", ct)
	}
	for _, link := range []string{"/api/alerts", "/api/alerts/critical", "/api/sessions", "/api/stats", "/api/health"} {
		if !strings.Contains(rec.Body.String(), link) {
			t.Errorf("root page must link %s", link)
		}
	}
}

func TestAlertsEndpointServesAllAddedAlerts(t *testing.T) {
	srv := newHandlerTestServer()
	srv.aggregator.AddAlert(&Alert{Level: "warning", Event: "signature_match", Rule: "R1", SrcIP: "10.0.0.1", Source: "zig"})
	srv.aggregator.AddAlert(&Alert{Level: "critical", Event: "block", Rule: "R2", SrcIP: "10.0.0.2", Source: "zig"})

	rec := httptest.NewRecorder()
	srv.handleAlerts(rec, httptest.NewRequest("GET", "/api/alerts", nil))

	var alerts []map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &alerts); err != nil {
		t.Fatalf("alerts must be a JSON array: %v", err)
	}
	if len(alerts) != 2 {
		t.Fatalf("want both alerts served, got %d", len(alerts))
	}
}

func TestCriticalAlertsFiltersByLevel(t *testing.T) {
	srv := newHandlerTestServer()
	srv.aggregator.AddAlert(&Alert{Level: "warning", Event: "signature_match", Rule: "R1", SrcIP: "10.0.0.1", Source: "zig"})
	srv.aggregator.AddAlert(&Alert{Level: "critical", Event: "block", Rule: "R2", SrcIP: "10.0.0.2", Source: "zig"})

	rec := httptest.NewRecorder()
	srv.handleCriticalAlerts(rec, httptest.NewRequest("GET", "/api/alerts/critical", nil))

	var alerts []map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &alerts); err != nil {
		t.Fatalf("critical alerts must be a JSON array: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("only the critical alert may pass the filter, got %d", len(alerts))
	}
	if alerts[0]["level"] != "critical" {
		t.Fatalf("filter leaked level %v", alerts[0]["level"])
	}
}

func TestAlertByHashRoundTripAndErrors(t *testing.T) {
	srv := newHandlerTestServer()
	srv.aggregator.AddAlert(&Alert{Level: "warning", Event: "signature_match", Rule: "R1", SrcIP: "10.0.0.1", Source: "zig"})
	hash := computeHash("R1", "10.0.0.1", "signature_match")

	rec := httptest.NewRecorder()
	srv.handleAlertByHash(rec, httptest.NewRequest("GET", "/api/alerts/"+hash, nil))
	if rec.Code != 200 {
		t.Fatalf("known hash must answer 200, got %d", rec.Code)
	}
	var alert map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &alert); err != nil {
		t.Fatalf("alert-by-hash must be JSON: %v", err)
	}
	if alert["hash"] != hash || alert["rule"] != "R1" {
		t.Fatalf("wrong alert served for hash: %v", alert)
	}

	miss := httptest.NewRecorder()
	srv.handleAlertByHash(miss, httptest.NewRequest("GET", "/api/alerts/0000000000000000", nil))
	if miss.Code != 404 {
		t.Fatalf("unknown hash must answer 404, got %d", miss.Code)
	}

	empty := httptest.NewRecorder()
	srv.handleAlertByHash(empty, httptest.NewRequest("GET", "/api/alerts/", nil))
	if empty.Code != 400 {
		t.Fatalf("empty hash must answer 400, got %d", empty.Code)
	}
}

func TestStatsCountsAlertsAndSessions(t *testing.T) {
	srv := newHandlerTestServer()
	alert := &Alert{Level: "warning", Event: "signature_match", Rule: "R1", SrcIP: "10.0.0.1", SessionID: 42, MonoNs: 1_000_000, Source: "zig"}
	srv.aggregator.AddAlert(alert)
	srv.correlator.AddEvent(alert)

	rec := httptest.NewRecorder()
	srv.handleStats(rec, httptest.NewRequest("GET", "/api/stats", nil))

	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("stats must be JSON: %v", err)
	}
	if body["total_alerts"] != float64(1) {
		t.Fatalf("total_alerts: want 1, got %v", body["total_alerts"])
	}
	if body["total_sessions"] != float64(1) {
		t.Fatalf("total_sessions: want 1, got %v", body["total_sessions"])
	}
	if _, ok := body["timestamp"]; !ok {
		t.Fatal("stats must carry a timestamp")
	}
}

func TestSessionsEndpointServesCorrelatedTimelines(t *testing.T) {
	srv := newHandlerTestServer()
	srv.correlator.AddEvent(&Alert{Level: "warning", Event: "signature_match", Rule: "R1", SrcIP: "10.0.0.1", SessionID: 7, MonoNs: 500, Source: "zig"})

	rec := httptest.NewRecorder()
	srv.handleSessions(rec, httptest.NewRequest("GET", "/api/sessions", nil))

	var sessions []map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &sessions); err != nil {
		t.Fatalf("sessions must be a JSON array: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("want the one correlated session, got %d", len(sessions))
	}
}

func TestSessionByIDRejectsNonNumericAndFormatsTimeline(t *testing.T) {
	srv := newHandlerTestServer()

	bad := httptest.NewRecorder()
	srv.handleSessionByID(bad, httptest.NewRequest("GET", "/api/sessions/abc", nil))
	if bad.Code != 400 {
		t.Fatalf("non-numeric session id must answer 400, got %d", bad.Code)
	}

	rec := httptest.NewRecorder()
	srv.handleSessionByID(rec, httptest.NewRequest("GET", "/api/sessions/7", nil))
	if rec.Code != 200 {
		t.Fatalf("numeric session id must answer 200, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/plain") {
		t.Fatalf("timeline must be text/plain, got %q", ct)
	}
	if !strings.Contains(rec.Body.String(), "Session 7") {
		t.Fatalf("timeline must name the session, got %q", rec.Body.String())
	}
}

func TestPurgeEndpointMethodAndBodyContract(t *testing.T) {
	srv := newHandlerTestServer()

	get := httptest.NewRecorder()
	srv.handlePurge(get, httptest.NewRequest("GET", "/api/purge", nil))
	if get.Code != 405 {
		t.Fatalf("GET on purge must answer 405, got %d", get.Code)
	}

	badBody := httptest.NewRecorder()
	srv.handlePurge(badBody, httptest.NewRequest("POST", "/api/purge", strings.NewReader("not-json")))
	if badBody.Code != 400 {
		t.Fatalf("malformed body must answer 400, got %d", badBody.Code)
	}

	ok := httptest.NewRecorder()
	srv.handlePurge(ok, httptest.NewRequest("POST", "/api/purge", strings.NewReader(`{"max_age_hours":1}`)))
	if ok.Code != 200 {
		t.Fatalf("valid purge must answer 200, got %d", ok.Code)
	}
	var body map[string]int
	if err := json.Unmarshal(ok.Body.Bytes(), &body); err != nil {
		t.Fatalf("purge response must be JSON: %v", err)
	}
	if body["purged"] != 0 {
		t.Fatalf("fresh alerts are newer than cutoff: want purged 0, got %d", body["purged"])
	}
}
