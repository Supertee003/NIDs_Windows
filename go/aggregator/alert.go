// ============================================================
// alert.go - AEGIS NIDS Alert types and dedup logic (Phase 18)
// ============================================================

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// Alert represents a normalized alert from any source (Zig/Python/Brain)
type Alert struct {
	ID           string    `json:"id"`
	Timestamp    int64     `json:"timestamp_ms"`     // epoch ms
	MonoNs       int64     `json:"mono_ns"`          // monotonic ns
	Level       string    `json:"level"`            // info/warn/error/critical
	Event        string    `json:"event"`            // BLOCK/MATCH/FORWARD/IP_BLOCKED
	Rule         string    `json:"rule,omitempty"`
	SrcIP        string    `json:"src_ip,omitempty"`
	SrcPort      int       `json:"src_port,omitempty"`
	SessionID    int64     `json:"session_id,omitempty"`
	RulesetVer   int64     `json:"ruleset_version,omitempty"`
	PayloadLen   int       `json:"payload_len,omitempty"`
	Source       string    `json:"source"`           // zig/python/brain
	Hash         string    `json:"hash"`             // dedup hash
	Count        int       `json:"count"`            // aggregation count
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
}

// AlertAggregator manages alert dedup and correlation
type AlertAggregator struct {
	alerts  map[string]*Alert // key: hash
	mu      sync.RWMutex
	maxSize int
}

// NewAlertAggregator creates a new aggregator
func NewAlertAggregator(maxSize int) *AlertAggregator {
	return &AlertAggregator{
		alerts:  make(map[string]*Alert),
		maxSize: maxSize,
	}
}

// computeHash generates a dedup hash from rule + src_ip + event type
func computeHash(rule, srcIP, eventType string) string {
	h := sha256.Sum256([]byte(rule + "|" + srcIP + "|" + eventType))
	return hex.EncodeToString(h[:8]) // first 8 bytes (16 hex chars)
}

// AddAlert adds or updates an alert (dedup by hash)
func (aa *AlertAggregator) AddAlert(alert *Alert) {
	alert.Hash = computeHash(alert.Rule, alert.SrcIP, alert.Event)
	alert.FirstSeen = time.Now()
	alert.LastSeen = time.Now()
	alert.Count = 1

	aa.mu.Lock()
	defer aa.mu.Unlock()

	// Check if alert already exists (dedup)
	if existing, ok := aa.alerts[alert.Hash]; ok {
		existing.Count++
		existing.LastSeen = time.Now()
		// Update severity if new is higher
		if severityRank(alert.Level) > severityRank(existing.Level) {
			existing.Level = alert.Level
		}
		return
	}

	// New alert - generate UUID if not set
	if alert.ID == "" {
		alert.ID = generateUUID()
	}
	aa.alerts[alert.Hash] = alert

	// Evict oldest if over capacity
	if len(aa.alerts) > aa.maxSize {
		aa.evictOldest()
	}
}

// severityRank returns numeric rank for severity comparison
func severityRank(level string) int {
	switch level {
	case "critical":
		return 4
	case "error":
		return 3
	case "warn":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

// evictOldest removes the oldest alert (by LastSeen)
func (aa *AlertAggregator) evictOldest() {
	var oldestKey string
	var oldestTime time.Time

	for key, alert := range aa.alerts {
		if oldestKey == "" || alert.LastSeen.Before(oldestTime) {
			oldestKey = key
			oldestTime = alert.LastSeen
		}
	}

	if oldestKey != "" {
		delete(aa.alerts, oldestKey)
	}
}

// GetAll returns all alerts as a slice
func (aa *AlertAggregator) GetAll() []*Alert {
	aa.mu.RLock()
	defer aa.mu.RUnlock()

	alerts := make([]*Alert, 0, len(aa.alerts))
	for _, a := range aa.alerts {
		alerts = append(alerts, a)
	}
	return alerts
}

// GetByHash returns a specific alert by hash
func (aa *AlertAggregator) GetByHash(hash string) *Alert {
	aa.mu.RLock()
	defer aa.mu.RUnlock()
	return aa.alerts[hash]
}

// GetCritical returns only critical-level alerts
func (aa *AlertAggregator) GetCritical() []*Alert {
	aa.mu.RLock()
	defer aa.mu.RUnlock()

	var critical []*Alert
	for _, a := range aa.alerts {
		if a.Level == "critical" {
			critical = append(critical, a)
		}
	}
	return critical
}

// Count returns total number of unique alerts
func (aa *AlertAggregator) Count() int {
	aa.mu.RLock()
	defer aa.mu.RUnlock()
	return len(aa.alerts)
}

// PurgeOlder removes alerts older than the given duration
func (aa *AlertAggregator) PurgeOlder(maxAge time.Duration) int {
	aa.mu.Lock()
	defer aa.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	purged := 0

	for key, alert := range aa.alerts {
		if alert.LastSeen.Before(cutoff) {
			delete(aa.alerts, key)
			purged++
		}
	}

	return purged
}
