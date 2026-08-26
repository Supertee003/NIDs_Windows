// ============================================================
// correlator.go - Cross-tier correlation engine (Phase 18)
// ============================================================
// Correlates events across tiers (Zig AC -> C++ bridge -> Python brain)
// using session_id for timeline reconstruction.

package main

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// SessionTimeline holds all events for a single session
type SessionTimeline struct {
	SessionID int64
	Events   []*Alert
	StartTs  time.Time
	EndTs    time.Time
}

// Correlator manages cross-tier event correlation
type Correlator struct {
	sessions map[int64]*SessionTimeline
	mu      sync.RWMutex
	maxAge  time.Duration
}

// NewCorrelator creates a new correlator
func NewCorrelator(maxAge time.Duration) *Correlator {
	return &Correlator{
		sessions: make(map[int64]*SessionTimeline),
		maxAge:   maxAge,
	}
}

// AddEvent adds an alert to a session timeline
func (c *Correlator) AddEvent(alert *Alert) {
	if alert.SessionID == 0 {
		return // No session ID - skip correlation
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	timeline, ok := c.sessions[alert.SessionID]
	if !ok {
		timeline = &SessionTimeline{
			SessionID: alert.SessionID,
			Events:    make([]*Alert, 0),
		}
		c.sessions[alert.SessionID] = timeline
	}

	timeline.Events = append(timeline.Events, alert)

	ts := time.Unix(0, alert.MonoNs*1000) // mono_ns to time
	if timeline.StartTs.IsZero() || ts.Before(timeline.StartTs) {
		timeline.StartTs = ts
	}
	if ts.After(timeline.EndTs) {
		timeline.EndTs = ts
	}
}

// GetSession returns the timeline for a specific session
func (c *Correlator) GetSession(sessionID int64) *SessionTimeline {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.sessions[sessionID]
}

// GetSessionCount returns the number of tracked sessions
func (c *Correlator) GetSessionCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.sessions)
}

// GetTopSessions returns sessions with the most events
func (c *Correlator) GetTopSessions(limit int) []*SessionTimeline {
	c.mu.RLock()
	defer c.mu.RUnlock()

	sessions := make([]*SessionTimeline, 0, len(c.sessions))
	for _, s := range c.sessions {
		sessions = append(sessions, s)
	}

	sort.Slice(sessions, func(i, j int) bool {
		return len(sessions[i].Events) > len(sessions[j].Events)
	})

	if limit > len(sessions) {
		limit = len(sessions)
	}
	return sessions[:limit]
}

// FindCorrelated finds events that match the same rule+IP across sessions
func (c *Correlator) FindCorrelated(rule, srcIP string) []*Alert {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var matched []*Alert
	for _, timeline := range c.sessions {
		for _, event := range timeline.Events {
			if event.Rule == rule && event.SrcIP == srcIP {
				matched = append(matched, event)
			}
		}
	}
	return matched
}

// PurgeOlder removes sessions older than maxAge
func (c *Correlator) PurgeOlder() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	cutoff := time.Now().Add(-c.maxAge)
	purged := 0

	for id, timeline := range c.sessions {
		if timeline.EndTs.Before(cutoff) {
			delete(c.sessions, id)
			purged++
		}
	}

	return purged
}

// FormatTimeline returns a human-readable timeline for a session
func (c *Correlator) FormatTimeline(sessionID int64) string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	timeline, ok := c.sessions[sessionID]
	if !ok {
		return fmt.Sprintf("Session %d not found", sessionID)
	}

	result := fmt.Sprintf("Session %d Timeline (%d events):\n", sessionID, len(timeline.Events))
	result += fmt.Sprintf("  Start: %s\n", timeline.StartTs.Format("15:04:05.000"))
	result += fmt.Sprintf("  End:   %s\n", timeline.EndTs.Format("15:04:05.000"))
	result += fmt.Sprintf("  Duration: %v\n", timeline.EndTs.Sub(timeline.StartTs))
	result += "  Events:\n"

	for i, event := range timeline.Events {
		result += fmt.Sprintf("    %d. [%s] %s: rule=%s src_ip=%s\n",
			i+1, event.Level, event.Event, event.Rule, event.SrcIP)
	}

	return result
}
