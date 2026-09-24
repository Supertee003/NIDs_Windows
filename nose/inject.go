package main

import (
	"fmt"
	"os"
	"sync/atomic"
	"time"
)

// runObserveInjection sends synthetic CanonicalEvent frames through the same
// FrameWriter and 109-byte serializer used by live Npcap capture. The fixture
// is intentionally alert-only: no rule ID, no signature-match event type, and
// no block policy request. It is for proving ingress/queue/policy/forensic
// linkage without creating a WFP host effect.
func runObserveInjection(pipe string, count int) error {
	if count < 1 {
		return fmt.Errorf("inject-observe count must be >= 1")
	}
	w := NewFrameWriter(pipe)
	if w == nil {
		return fmt.Errorf("cannot create canonical frame writer")
	}

	for i := 0; i < count; i++ {
		now := time.Now()
		ev := &CanonicalEvent{
			EventID:           atomic.AddUint64(&eventSequence, 1),
			TimestampMS:       uint64(now.UnixMilli()),
			MonotonicNS:       uint64(now.UnixNano()),
			Source:            SourceNpcapSensor,
			SourceIP:          0xC0A80164, // 192.168.1.100
			SourcePort:        uint16(49152 + i),
			DestIP:            0xAC1F0A0A, // 172.31.10.10
			DestPort:          443,
			Protocol:          6,
			EventType:         TypeForward,
			Severity:          1, // canonical High/notice path; no signature rule
			RuleID:            0,
			PolicyAction:      ActionLogOnly,
			DefconImpact:      5,
			IsPipe:            0,
			EnforcementStatus: 0,
		}
		delivered := false
		for attempt := 0; attempt < 20 && !delivered; attempt++ {
			delivered = w.Send(ev)
			if !delivered {
				// Observe-only proof is deterministic by contract; unlike
				// live capture, it may wait for the single-instance Zig
				// reader to hand off/reopen the pipe.
				time.Sleep(100 * time.Millisecond)
			}
		}
		if i+1 < count {
			time.Sleep(20 * time.Millisecond)
		}
	}

	sent, dropped := w.Stats()
	fmt.Fprintf(os.Stderr, "[NOSE INJECT] observe-only sent=%d dropped=%d count=%d\n", sent, dropped, count)
	if sent != uint64(count) {
		return fmt.Errorf("canonical observe injection incomplete: sent=%d expected=%d dropped=%d", sent, count, dropped)
	}
	return nil
}
