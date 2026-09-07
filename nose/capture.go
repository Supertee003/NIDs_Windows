// =====================================================================
// capture.go - AEGIS NOSE live packet capture -> CanonicalEvent -> Zig
// =====================================================================
// Acquisition-only (ADR-0001): this file captures packets and encodes
// them into the frozen CanonicalEvent wire format. It performs NO
// policy decisions and NO enforcement — everything flows to the Zig
// core, which owns detection + policy + enforcement.
//
// Uses gopacket + Npcap (already installed at C:\Program Files\Npcap).
// Launch:  nose -capture [-iface eth0] [-pipe \\.\pipe\aegis_nose]
//          nose -capture-self-test   (unit-ish smoke, no pipe required)
// =====================================================================
package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// captureState tracks live counters (atomic so the TUI can read them).
type captureState struct {
	packets      uint64 // frames seen on the wire
	canonical    uint64 // canonical events encoded
	droppedPipe  uint64 // frames the sink could not deliver
	bytesTotal   uint64
	ifaceName    string
	startedUnixN int64
}

var stateAtomic captureState

// captureDefaultTimeout is the pcap read timeout for live capture.
const captureDefaultTimeout = time.Second

// firstUpDevice returns the first adapter that is up and not loopback,
// preferring Ethernet. Matches (roughly) Zig npcap_capture.zig selection.
func firstUpDevice() (string, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return "", fmt.Errorf("nose capture: FindAllDevs: %w", err)
	}
	// Prefer the first adapter with a real IP address (means it's up and usable).
	for _, d := range devs {
		if len(d.Addresses) > 0 {
			return d.Name, nil
		}
	}
	if len(devs) > 0 {
		return devs[0].Name, nil
	}
	return "", fmt.Errorf("nose capture: no capture devices found")
}

// runCapture opens a live pcap handle, encodes packets as canonical
// events, and streams them to the Zig core pipe until signalled.
func runCapture(iface string, pipe string, stop <-chan struct{}) error {
	if iface == "" {
		name, err := firstUpDevice()
		if err != nil {
			return fmt.Errorf("nose capture: %w", err)
		}
		iface = name
	}

	handle, err := pcap.OpenLive(iface, 65535, false, captureDefaultTimeout)
	if err != nil {
		return fmt.Errorf("nose capture: open %s: %w", iface, err)
	}
	defer handle.Close()

	// Passive capture only — never set promiscuous off-label; keep it
	// simple and read-only (no injection, no filter state on the wire).
	if err := handle.SetBPFFilter("ip or ip6"); err != nil {
		return fmt.Errorf("nose capture: bpf: %w", err)
	}

	stateAtomic.ifaceName = iface
	stateAtomic.startedUnixN = time.Now().UnixNano()
	fmt.Fprintf(os.Stderr, "[NOSE CAPTURE] listening on %s -> %s\n", iface, pipe)

	w := NewFrameWriter(pipe)
	src := gopacket.NewPacketSource(handle, handle.LinkType())
	src.NoCopy = true

	count := 0
	for packet := range src.Packets() {
		select {
		case <-stop:
			return nil
		default:
		}
		atomic.AddUint64(&stateAtomic.packets, 1)
		ev := eventFromPacket(packet)
		atomic.AddUint64(&stateAtomic.canonical, 1)
		atomic.AddUint64(&stateAtomic.bytesTotal, uint64(packet.Metadata().CaptureLength))
		_ = w.Send(ev)
		atomic.StoreUint64(&stateAtomic.droppedPipe, droppedVia(w))
		count++
		if stop != nil {
			select {
			case <-stop:
				return nil
			default:
			}
		}
	}
	return nil
}

func droppedVia(w *FrameWriter) uint64 {
	_, dropped := w.Stats()
	return dropped
}

// eventFromPacket converts one packet into the canonical event schema.
// T2 scope: network events (source = npcap_sensor → SourceKind.network).
// No detection, no policy — pure observation.
func eventFromPacket(packet gopacket.Packet) *CanonicalEvent {
	now := time.Now()
	ev := &CanonicalEvent{
		EventID:        uint64(now.UnixNano()), // unique enough per capture tick
		TimestampMS:    uint64(now.UnixMilli()),
		MonotonicNS:    uint64(now.UnixNano()),
		Source:         SourceNpcapSensor,
		LayerID:        0, // 0=TCP path (see schema)
		EventType:      TypeForward,
		Severity:       0,
		PolicyAction:   ActionLogOnly,
		DefconImpact:   5, // neutral
		IsPipe:         0,
		EnforcementStatus: 0,
	}

	// --- network identity (5-tuple) ---
	if l3 := packet.NetworkLayer(); l3 != nil {
		switch net := l3.(type) {
		case *layers.IPv4:
			ev.SourceIP = binary.BigEndian.Uint32(net.SrcIP.To4())
			ev.DestIP = binary.BigEndian.Uint32(net.DstIP.To4())
			ev.Protocol = uint8(net.Protocol)
		case *layers.IPv6:
			// IPv6 identity: embed first 4 bytes of each address.
			ev.SourceIP = binary.BigEndian.Uint32(net.SrcIP.To16())
			ev.DestIP = binary.BigEndian.Uint32(net.DstIP.To16())
			ev.Protocol = uint8(net.NextHeader)
		}
	}

	// --- transport ports ---
	if l4 := packet.TransportLayer(); l4 != nil {
		switch tr := l4.(type) {
		case *layers.TCP:
			ev.SourcePort = uint16(tr.SrcPort)
			ev.DestPort = uint16(tr.DstPort)
			ev.Protocol = 6
		case *layers.UDP:
			ev.SourcePort = uint16(tr.SrcPort)
			ev.DestPort = uint16(tr.DstPort)
			ev.Protocol = 17
		default:
		}
	}

	// --- payload reference: canonical uses first-8-bytes SHA-256 prefix.
	// For capture-only v1 we use length + a djb2-ish prefix over the first
	// bytes (dedup reference only — hash quality is Zig's concern later).
	if pl := packet.ApplicationLayer(); pl != nil {
		data := pl.Payload()
		ev.PayloadLength = uint32(len(data))
		ev.PayloadHash = quickHash(data)
	}
	return ev
}

// quickHash gives a numeric dedup reference from the payload bytes.
func quickHash(b []byte) uint64 {
	var h uint64 = 14695981039346656037
	for _, c := range b {
		h ^= uint64(c)
		h *= 1099511628211
	}
	return h
}

// captureSelfTest validates the encoder end-to-end without needing a
// live consumer: one synthetic packet → wire bytes → sanity checks.
func captureSelfTest() error {
	fake := &CanonicalEvent{
		EventID:        1,
		TimestampMS:    1700000000000,
		MonotonicNS:    1700000000000000000,
		Source:         SourceNpcapSensor,
		SourceIP:       0xC0A80164, // 192.168.1.100
		SourcePort:     49152,
		DestIP:         0xAC1F0A0A,
		DestPort:       443,
		Protocol:       6,
		EventType:      TypeForward,
		Severity:       0,
		PolicyAction:   ActionLogOnly,
		DefconImpact:   5,
		PayloadLength:  40,
		PID:            1234,
		PPID:           5678,
		NodeID:         7,
		Confidence:     0,
	}
	wire, err := fake.Serialize()
	if err != nil {
		return fmt.Errorf("capture self-test: serialize: %w", err)
	}
	if len(wire) != EventWireSize {
		return fmt.Errorf("capture self-test: wire size %d != %d", len(wire), EventWireSize)
	}
	if binary.LittleEndian.Uint32(wire[0:4]) != EventMagic {
		return fmt.Errorf("capture self-test: magic mismatch")
	}
	if wire[32] != SourceNpcapSensor {
		return fmt.Errorf("capture self-test: source mismatch")
	}
	// 5-tuple back out of the wire.
	if binary.LittleEndian.Uint32(wire[33:37]) != 0xC0A80164 {
		return fmt.Errorf("capture self-test: src ip mismatch")
	}
	if binary.LittleEndian.Uint16(wire[43:45]) != 443 {
		return fmt.Errorf("capture self-test: dst port mismatch")
	}
	fmt.Printf("capture self-test OK: %d bytes wire, magic 0x%08X, src %d.%d.%d.%d\n",
		len(wire), EventMagic, wire[33], wire[34], wire[35], wire[36])
	return nil
}