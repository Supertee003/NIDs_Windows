// =====================================================================
// producer_identity.go - Go Nose acquisition identity issuance (S3)
// =====================================================================
// Acquisition-only (ADR-0001). This file issues the v3 provenance tuple
// stamped on live capture frames. It does not inspect packets, decide
// policy, or authorize enforcement. The tuple is an identity, not a trust
// signature: Zig ingress still owns admission/dedup.
//
// The restart generation is durable and per-interface. A lock file makes
// concurrent starts fail closed instead of issuing the same generation to
// two processes. A stale lock or unreadable state is an explicit startup
// error, never a silent fallback to generation 1.
// =====================================================================
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

const (
	producerStateEnv     = "AEGIS_NOSE_STATE_FILE"
	producerStateVersion = 1
)

type producerState struct {
	Version     uint32            `json:"version"`
	Generations map[string]uint32 `json:"generations"`
	UpdatedUnix int64             `json:"updated_unix"`
}

var captureSequence uint64

// nextCaptureSequence is the dedicated v3 producer counter. It is separate
// from the base CanonicalEvent event_id so ingress can reason about producer
// continuity instead of reusing a detection identity.
func nextCaptureSequence() uint64 {
	return atomic.AddUint64(&captureSequence, 1)
}

func interfaceIDFor(iface string) uint32 {
	var h uint32 = 0x811c9dc5
	for i := 0; i < len(iface); i++ {
		h ^= uint32(iface[i])
		h *= 0x01000193
	}
	return h
}

func producerStatePath() (string, error) {
	var path string
	if raw := os.Getenv(producerStateEnv); raw != "" {
		abs, err := filepath.Abs(raw)
		if err != nil {
			return "", fmt.Errorf("producer state path: %w", err)
		}
		path = abs
	} else {
		dir, err := os.UserConfigDir()
		if err != nil {
			return "", fmt.Errorf("producer state dir: %w", err)
		}
		path = filepath.Join(dir, "AEGIS-NIDS", "nose_producer_generation.json")
	}
	// Create only the dedicated state directory. No repository/tree writes.
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", fmt.Errorf("producer state dir %s: %w", filepath.Dir(path), err)
	}
	return path, nil
}

// acquireProducerLock is intentionally non-blocking. Two concurrent starts
// must not both increment from the same generation; the loser fails startup
// visibly. A lock left behind by a crashed process is likewise explicit.
func acquireProducerLock(statePath string) (*os.File, string, error) {
	lockPath := statePath + ".lock"
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, lockPath, fmt.Errorf("producer state lock %s (remove stale lock only after confirming no Nose is running): %w", lockPath, err)
	}
	return f, lockPath, nil
}

// issueProducerGeneration advances the durable per-interface generation.
// Callers hold the exclusive lock path; the first live start receives 1.
func issueProducerGeneration(iface, statePath string, nowUnix int64) (uint32, error) {
	if iface == "" {
		return 0, fmt.Errorf("producer generation: empty interface")
	}
	if statePath == "" {
		return 0, fmt.Errorf("producer generation: empty state path")
	}

	lock, lockPath, err := acquireProducerLock(statePath)
	if err != nil {
		return 0, err
	}
	defer func() {
		_ = lock.Close()
		_ = os.Remove(lockPath)
	}()

	st := producerState{Version: producerStateVersion, Generations: map[string]uint32{}}
	raw, err := os.ReadFile(statePath)
	if err == nil {
		if err := json.Unmarshal(raw, &st); err != nil {
			return 0, fmt.Errorf("producer state corrupt %s: %w", statePath, err)
		}
		if st.Version != producerStateVersion || st.Generations == nil {
			return 0, fmt.Errorf("producer state unsupported version/shape in %s", statePath)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return 0, fmt.Errorf("producer state read %s: %w", statePath, err)
	}

	next := st.Generations[iface] + 1
	if next == 0 {
		return 0, fmt.Errorf("producer generation overflow for interface %q", iface)
	}
	st.Generations[iface] = next
	st.UpdatedUnix = nowUnix
	if st.UpdatedUnix < 0 {
		return 0, fmt.Errorf("producer generation: invalid epoch")
	}
	encoded, err := json.Marshal(st)
	if err != nil {
		return 0, fmt.Errorf("producer state encode: %w", err)
	}

	tmp := statePath + ".tmp"
	if err := os.WriteFile(tmp, encoded, 0o600); err != nil {
		return 0, fmt.Errorf("producer state temp write: %w", err)
	}
	if _, err := os.Stat(statePath); err == nil {
		if err := os.Remove(statePath); err != nil {
			_ = os.Remove(tmp)
			return 0, fmt.Errorf("producer state replace: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		_ = os.Remove(tmp)
		return 0, fmt.Errorf("producer state stat: %w", err)
	}
	if err := os.Rename(tmp, statePath); err != nil {
		_ = os.Remove(tmp)
		return 0, fmt.Errorf("producer state rename: %w", err)
	}
	return next, nil
}

// newLiveCaptureProvenance issues the tuple for one live capture process.
// The returned epoch is start-time metadata; ordering is owned by the
// dedicated sequence plus the durable generation.
func newLiveCaptureProvenance(iface string) (captureProvenance, error) {
	now := time.Now()
	epoch := uint32(now.Unix())
	id := interfaceIDFor(iface)
	if epoch == 0 || id == 0 {
		return captureProvenance{}, fmt.Errorf("producer identity: zero epoch/interface id")
	}
	statePath, err := producerStatePath()
	if err != nil {
		return captureProvenance{}, err
	}
	generation, err := issueProducerGeneration(iface, statePath, now.Unix())
	if err != nil {
		return captureProvenance{}, err
	}
	return captureProvenance{
		epoch:       epoch,
		generation:  generation,
		interfaceID: id,
	}, nil
}
