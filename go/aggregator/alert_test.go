package main

import (
	"testing"
	"time"
)

func TestComputeHash(t *testing.T) {
	hash1 := computeHash("SQL_INJECTION", "192.168.1.100", "BLOCK")
	hash2 := computeHash("SQL_INJECTION", "192.168.1.100", "BLOCK")
	hash3 := computeHash("SQL_INJECTION", "192.168.1.101", "BLOCK")
	hash4 := computeHash("XSS", "192.168.1.100", "BLOCK")

	if hash1 != hash2 {
		t.Error("Same inputs should produce same hash")
	}
	if hash1 == hash3 {
		t.Error("Different IPs should produce different hashes")
	}
	if hash1 == hash4 {
		t.Error("Different rules should produce different hashes")
	}
	if len(hash1) != 16 {
		t.Errorf("Hash should be 16 hex chars, got %d", len(hash1))
	}
}

func TestSeverityRank(t *testing.T) {
	tests := []struct {
		level    string
		expected int
	}{
		{"critical", 4},
		{"error", 3},
		{"warn", 2},
		{"info", 1},
		{"unknown", 0},
	}
	for _, tt := range tests {
		if got := severityRank(tt.level); got != tt.expected {
			t.Errorf("severityRank(%s) = %d, want %d", tt.level, got, tt.expected)
		}
	}
}

func TestAddAlertNew(t *testing.T) {
	agg := NewAlertAggregator(100)
	alert := &Alert{
		Level:  "critical",
		Event:  "BLOCK",
		Rule:   "SQL_INJECTION",
		SrcIP:  "192.168.1.100",
		Source: "zig",
	}
	agg.AddAlert(alert)

	if agg.Count() != 1 {
		t.Errorf("Expected 1 alert, got %d", agg.Count())
	}
}

func TestAddAlertDedup(t *testing.T) {
	agg := NewAlertAggregator(100)

	// Add same alert twice (same rule + IP + event)
	for i := 0; i < 3; i++ {
		agg.AddAlert(&Alert{
			Level: "critical",
			Event: "BLOCK",
			Rule:  "SQL_INJECTION",
			SrcIP: "192.168.1.100",
		})
	}

	if agg.Count() != 1 {
		t.Errorf("Dedup: expected 1 alert, got %d", agg.Count())
	}

	alerts := agg.GetAll()
	if alerts[0].Count != 3 {
		t.Errorf("Expected count=3, got %d", alerts[0].Count)
	}
}

func TestAddAlertDifferentIPs(t *testing.T) {
	agg := NewAlertAggregator(100)
	agg.AddAlert(&Alert{Rule: "R1", SrcIP: "10.0.0.1", Event: "BLOCK"})
	agg.AddAlert(&Alert{Rule: "R1", SrcIP: "10.0.0.2", Event: "BLOCK"})
	agg.AddAlert(&Alert{Rule: "R1", SrcIP: "10.0.0.3", Event: "BLOCK"})

	if agg.Count() != 3 {
		t.Errorf("Expected 3 alerts (different IPs), got %d", agg.Count())
	}
}

func TestGetCritical(t *testing.T) {
	agg := NewAlertAggregator(100)
	agg.AddAlert(&Alert{Level: "critical", Rule: "R1", SrcIP: "10.0.0.1", Event: "BLOCK"})
	agg.AddAlert(&Alert{Level: "info", Rule: "R2", SrcIP: "10.0.0.2", Event: "FORWARD"})
	agg.AddAlert(&Alert{Level: "critical", Rule: "R3", SrcIP: "10.0.0.3", Event: "BLOCK"})

	critical := agg.GetCritical()
	if len(critical) != 2 {
		t.Errorf("Expected 2 critical alerts, got %d", len(critical))
	}
}

func TestEvictOldest(t *testing.T) {
	agg := NewAlertAggregator(2) // Small capacity
	agg.AddAlert(&Alert{Rule: "R1", SrcIP: "10.0.0.1", Event: "BLOCK"})
	time.Sleep(1 * time.Millisecond)
	agg.AddAlert(&Alert{Rule: "R2", SrcIP: "10.0.0.2", Event: "BLOCK"})
	time.Sleep(1 * time.Millisecond)
	agg.AddAlert(&Alert{Rule: "R3", SrcIP: "10.0.0.3", Event: "BLOCK"})

	if agg.Count() > 2 {
		t.Errorf("Expected max 2 alerts (eviction), got %d", agg.Count())
	}
}

func TestPurgeOlder(t *testing.T) {
	agg := NewAlertAggregator(100)
	agg.AddAlert(&Alert{Rule: "R1", SrcIP: "10.0.0.1", Event: "BLOCK"})

	// Manually set LastSeen to 2 hours ago
	for _, a := range agg.GetAll() {
		a.LastSeen = time.Now().Add(-2 * time.Hour)
	}

	purged := agg.PurgeOlder(1 * time.Hour)
	if purged != 1 {
		t.Errorf("Expected 1 purged, got %d", purged)
	}
	if agg.Count() != 0 {
		t.Errorf("Expected 0 alerts after purge, got %d", agg.Count())
	}
}

func TestGetByHash(t *testing.T) {
	agg := NewAlertAggregator(100)
	alert := &Alert{Rule: "R1", SrcIP: "10.0.0.1", Event: "BLOCK"}
	agg.AddAlert(alert)

	hash := computeHash("R1", "10.0.0.1", "BLOCK")
	found := agg.GetByHash(hash)
	if found == nil {
		t.Error("Expected to find alert by hash")
	}
	if found.Rule != "R1" {
		t.Errorf("Expected rule R1, got %s", found.Rule)
	}

	nonexistent := agg.GetByHash("nonexistent")
	if nonexistent != nil {
		t.Error("Expected nil for nonexistent hash")
	}
}
