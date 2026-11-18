// ============================================================
// collector.go - NDJSON file watcher for AEGIS forensic log (Phase 18)
// ============================================================
// Watches logs/aegis_core.ndjson for new alerts and feeds them
// to the AlertAggregator for dedup and correlation.

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
)

// LogEntry represents a parsed NDJSON line from the forensic log
type LogEntry struct {
	TimestampMs  int64  `json:"ts_ms"`
	MonoNs       int64  `json:"mono_ns"`
	Level        string `json:"level"`
	Event        string `json:"event"`
	Rule         string `json:"rule,omitempty"`
	SrcIP        string `json:"src_ip,omitempty"`
	SrcPort      int    `json:"src_port,omitempty"`
	SessionID    int64  `json:"session_id,omitempty"`
	RulesetVer   int64  `json:"ruleset_version,omitempty"`
	PayloadLen   int    `json:"payload_len,omitempty"`
	Extra        string `json:"extra,omitempty"`
}

// Collector watches the NDJSON log file and parses new entries
type Collector struct {
	filePath   string
	aggregator *AlertAggregator
	watcher    *fsnotify.Watcher
	offset     int64
	mu         sync.Mutex
	stopCh     chan struct{}

	// DEADCODE-QUARANTINE: real accounting for the health endpoint (was a
	// hardcoded zero block, so a supervisor could not see ingest dying).
	ingested     atomic.Uint64 // NDJSON lines parsed into alerts
	parseErrors  atomic.Uint64 // non-empty lines that failed to parse
	lastIngestMs atomic.Int64  // Unix ms of the last successful ingest; 0 = never
}

// NewCollector creates a new log file collector
func NewCollector(filePath string, aggregator *AlertAggregator) (*Collector, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create watcher: %w", err)
	}

	c := &Collector{
		filePath:   filePath,
		aggregator: aggregator,
		watcher:    watcher,
		stopCh:     make(chan struct{}),
	}

	// Ensure directory exists for watching
	dir := filepath.Dir(filePath)
	if err := watcher.Add(dir); err != nil {
		watcher.Close()
		return nil, fmt.Errorf("failed to watch directory %s: %w", dir, err)
	}

	return c, nil
}

// Start begins collecting alerts from the log file
func (c *Collector) Start() error {
	// Seek to end of file (only new alerts)
	file, err := os.Open(c.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist yet - wait for it
			go c.waitForFile()
			return nil
		}
		return err
	}

	info, _ := file.Stat()
	c.offset = info.Size()
	file.Close()

	go c.watch()
	return nil
}

// waitForFile polls until the log file appears
func (c *Collector) waitForFile() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			if _, err := os.Stat(c.filePath); err == nil {
				go c.watch()
				return
			}
		}
	}
}

// watch monitors the file for changes and reads new lines
func (c *Collector) watch() {
	for {
		select {
		case <-c.stopCh:
			return
		case event, ok := <-c.watcher.Events:
			if !ok {
				return
			}
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
				c.readNewLines()
			}
		case err, ok := <-c.watcher.Errors:
			if !ok {
				return
			}
			fmt.Printf("[COLLECTOR] Watcher error: %v\n", err)
		}
	}
}

// readNewLines reads all new lines from the current offset
func (c *Collector) readNewLines() {
	c.mu.Lock()
	defer c.mu.Unlock()

	file, err := os.Open(c.filePath)
	if err != nil {
		return
	}
	defer file.Close()

	_, err = file.Seek(c.offset, 0)
	if err != nil {
		return
	}

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024*1024), 10*1024*1024) // 10MB max line

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var entry LogEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			c.parseErrors.Add(1) // surfaced as counters.errors in /api/health
			continue
		}

		// Convert to Alert and add to aggregator
		alert := &Alert{
			Timestamp:  entry.TimestampMs,
			MonoNs:     entry.MonoNs,
			Level:      entry.Level,
			Event:      entry.Event,
			Rule:       entry.Rule,
			SrcIP:      entry.SrcIP,
			SrcPort:    entry.SrcPort,
			SessionID:  entry.SessionID,
			RulesetVer: entry.RulesetVer,
			PayloadLen: entry.PayloadLen,
			Source:     "zig",
		}

		c.aggregator.AddAlert(alert)
		c.ingested.Add(1)
		c.lastIngestMs.Store(time.Now().UnixMilli())

		// Log critical alerts to console
		if alert.Level == "critical" {
			fmt.Printf("[CRITICAL] %s: rule=%s src_ip=%s session=%d\n",
				alert.Event, alert.Rule, alert.SrcIP, alert.SessionID)
		}
	}

	// Update offset
	if info, err := file.Stat(); err == nil {
		c.offset = info.Size()
	}
}

// Stop stops the collector
func (c *Collector) Stop() {
	close(c.stopCh)
	c.watcher.Close()
}

// Stats reports the collector's real ingest accounting for /api/health.
// lastIngestMs is 0 until the first successful parse (honest "never").
func (c *Collector) Stats() (ingested uint64, parseErrors uint64, lastIngestMs int64) {
	return c.ingested.Load(), c.parseErrors.Load(), c.lastIngestMs.Load()
}
