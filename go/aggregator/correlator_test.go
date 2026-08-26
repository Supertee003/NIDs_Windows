package main

import (
	"testing"
	"time"
)

func TestCorrelatorAddEvent(t *testing.T) {
	corr := NewCorrelator(24 * time.Hour)

	alert1 := &Alert{SessionID: 100, Event: "BLOCK", Rule: "R1", SrcIP: "10.0.0.1"}
	alert2 := &Alert{SessionID: 100, Event: "MATCH", Rule: "R2", SrcIP: "10.0.0.1"}
	alert3 := &Alert{SessionID: 200, Event: "BLOCK", Rule: "R3", SrcIP: "10.0.0.2"}

	corr.AddEvent(alert1)
	corr.AddEvent(alert2)
	corr.AddEvent(alert3)

	if corr.GetSessionCount() != 2 {
		t.Errorf("Expected 2 sessions, got %d", corr.GetSessionCount())
	}
}

func TestCorrelatorGetSession(t *testing.T) {
	corr := NewCorrelator(24 * time.Hour)

	alert := &Alert{SessionID: 42, Event: "BLOCK", Rule: "R1", SrcIP: "10.0.0.1", MonoNs: 1000000}
	corr.AddEvent(alert)

	timeline := corr.GetSession(42)
	if timeline == nil {
		t.Fatal("Expected session 42 to exist")
	}
	if len(timeline.Events) != 1 {
		t.Errorf("Expected 1 event, got %d", len(timeline.Events))
	}
}

func TestCorrelatorGetSessionNotFound(t *testing.T) {
	corr := NewCorrelator(24 * time.Hour)
	timeline := corr.GetSession(999)
	if timeline != nil {
		t.Error("Expected nil for nonexistent session")
	}
}

func TestCorrelatorGetTopSessions(t *testing.T) {
	corr := NewCorrelator(24 * time.Hour)

	// Session 1: 5 events
	for i := 0; i < 5; i++ {
		corr.AddEvent(&Alert{SessionID: 1, Event: "MATCH", MonoNs: int64(i * 1000)})
	}
	// Session 2: 2 events
	for i := 0; i < 2; i++ {
		corr.AddEvent(&Alert{SessionID: 2, Event: "MATCH", MonoNs: int64(i * 1000)})
	}
	// Session 3: 3 events
	for i := 0; i < 3; i++ {
		corr.AddEvent(&Alert{SessionID: 3, Event: "MATCH", MonoNs: int64(i * 1000)})
	}

	top := corr.GetTopSessions(2)
	if len(top) != 2 {
		t.Fatalf("Expected 2 sessions, got %d", len(top))
	}
	if len(top[0].Events) != 5 {
		t.Errorf("Expected top session with 5 events, got %d", len(top[0].Events))
	}
}

func TestCorrelatorFindCorrelated(t *testing.T) {
	corr := NewCorrelator(24 * time.Hour)

	corr.AddEvent(&Alert{SessionID: 1, Rule: "R1", SrcIP: "10.0.0.1", Event: "BLOCK"})
	corr.AddEvent(&Alert{SessionID: 2, Rule: "R1", SrcIP: "10.0.0.1", Event: "MATCH"})
	corr.AddEvent(&Alert{SessionID: 3, Rule: "R2", SrcIP: "10.0.0.2", Event: "BLOCK"})

	matched := corr.FindCorrelated("R1", "10.0.0.1")
	if len(matched) != 2 {
		t.Errorf("Expected 2 correlated events, got %d", len(matched))
	}
}

func TestCorrelatorPurgeOlder(t *testing.T) {
	corr := NewCorrelator(1 * time.Millisecond) // Very short max age

	corr.AddEvent(&Alert{SessionID: 1, Event: "BLOCK", MonoNs: 1000})
	time.Sleep(10 * time.Millisecond)

	purged := corr.PurgeOlder()
	if purged != 1 {
		t.Errorf("Expected 1 purged session, got %d", purged)
	}
	if corr.GetSessionCount() != 0 {
		t.Errorf("Expected 0 sessions after purge, got %d", corr.GetSessionCount())
	}
}

func TestCorrelatorFormatTimeline(t *testing.T) {
	corr := NewCorrelator(24 * time.Hour)

	corr.AddEvent(&Alert{SessionID: 42, Event: "BLOCK", Rule: "R1", SrcIP: "10.0.0.1", MonoNs: 1000000})
	corr.AddEvent(&Alert{SessionID: 42, Event: "MATCH", Rule: "R2", SrcIP: "10.0.0.1", MonoNs: 2000000})

	result := corr.FormatTimeline(42)
	if result == "" {
		t.Error("Expected non-empty timeline")
	}

	// Nonexistent session
	result = corr.FormatTimeline(999)
	if result == "" {
		t.Error("Expected non-empty string for nonexistent session")
	}
}
