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
//
//	nose -capture-self-test   (unit-ish smoke, no pipe required)
//
// =====================================================================
package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
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
var eventSequence uint64

// captureDefaultTimeout is the pcap read timeout for live capture.
const captureDefaultTimeout = time.Second

// firstUpDevice returns the first adapter that is up and not loopback,
// preferring Ethernet. Matches (roughly) Zig npcap_capture.zig selection.
func firstUpDevice() (string, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return "", fmt.Errorf("nose capture: FindAllDevs: %w", err)
	}
	// Prefer physical adapters over virtual host-only adapters. The first
	// pcap device is often Hyper-V/VMware and may have an IP but no traffic
	// for the operator's active route.
	for _, d := range devs {
		if len(d.Addresses) == 0 {
			continue
		}
		label := strings.ToLower(d.Name + " " + d.Description)
		if !strings.Contains(label, "wan miniport") &&
			!strings.Contains(label, "hyper-v") &&
			!strings.Contains(label, "vmware") &&
			!strings.Contains(label, "bluetooth") &&
			!strings.Contains(label, "wi-fi direct") &&
			!strings.Contains(label, "teamviewer") &&
			!strings.Contains(label, "loopback") &&
			!strings.Contains(label, "npcap loopback") {
			fmt.Fprintf(os.Stderr, "[NOSE CAPTURE] auto-selected physical adapter: %s (%s)\n", d.Name, d.Description)
			return d.Name, nil
		}
	}
	for _, d := range devs {
		if len(d.Addresses) > 0 {
			fmt.Fprintf(os.Stderr, "[NOSE CAPTURE] auto-selected fallback adapter: %s (%s)\n", d.Name, d.Description)
			return d.Name, nil
		}
	}
	if len(devs) > 0 {
		return devs[0].Name, nil
	}
	return "", fmt.Errorf("nose capture: no capture devices found")
}

func printCaptureDevices() error {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return fmt.Errorf("FindAllDevs: %w", err)
	}
	fmt.Fprintf(os.Stderr, "[NOSE DEVICES] found=%d\n", len(devs))
	for i, d := range devs {
		fmt.Fprintf(os.Stderr, "[NOSE DEVICES] #%d name=%s description=%q addresses=%d\n", i, d.Name, d.Description, len(d.Addresses))
		for _, a := range d.Addresses {
			fmt.Fprintf(os.Stderr, "[NOSE DEVICES] #%d address=%s netmask=%s\n", i, a.IP, a.Netmask)
		}
	}
	return nil
}

func validateCaptureInterface(iface string) error {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return fmt.Errorf("FindAllDevs: %w", err)
	}
	for _, d := range devs {
		if d.Name == iface {
			return nil
		}
	}
	return fmt.Errorf("interface %q not found; run --list-devices and pass the exact Npcap name", iface)
}

// runCapture opens a live pcap handle, encodes packets as canonical
// events, and streams them to the Zig core pipe until signalled.
func runCapture(iface string, pipe string, stop <-chan struct{}) error {
	if err := loadNoseSignatureRules(); err != nil {
		fmt.Fprintf(os.Stderr, "[NOSE RULES] disabled: %v\n", err)
	}
	if iface == "" {
		name, err := firstUpDevice()
		if err != nil {
			return fmt.Errorf("nose capture: %w", err)
		}
		iface = name
	} else if err := validateCaptureInterface(iface); err != nil {
		return fmt.Errorf("nose capture: %w", err)
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

	count := 0
	for {
		select {
		case <-stop:
			fmt.Fprintln(os.Stderr, "[NOSE CAPTURE] stop requested")
			return nil
		default:
		}

		data, captureInfo, readErr := handle.ReadPacketData()
		if readErr != nil {
			// Read timeout is expected because captureDefaultTimeout is finite;
			// it lets us observe stop without spinning or blocking forever.
			if strings.Contains(strings.ToLower(readErr.Error()), "timeout") {
				continue
			}
			fmt.Fprintf(os.Stderr, "[NOSE CAPTURE] ReadPacketData failed: %v\n", readErr)
			return fmt.Errorf("nose capture: ReadPacketData: %w", readErr)
		}
		packet := gopacket.NewPacket(data, handle.LinkType(), gopacket.NoCopy)
		atomic.AddUint64(&stateAtomic.packets, 1)
		if count == 0 {
			fmt.Fprintf(os.Stderr, "[NOSE CAPTURE] first packet captured: len=%d\n", captureInfo.CaptureLength)
		}
		ev := eventFromPacket(packet)
		classifyNosePacket(ev, packet)
		atomic.AddUint64(&stateAtomic.canonical, 1)
		atomic.AddUint64(&stateAtomic.bytesTotal, uint64(captureInfo.CaptureLength))
		_ = w.Send(ev)
		atomic.StoreUint64(&stateAtomic.droppedPipe, droppedVia(w))
		count++
		if count%100 == 0 {
			fmt.Fprintf(os.Stderr, "[NOSE CAPTURE] packets=%d canonical=%d dropped=%d\n", count, atomic.LoadUint64(&stateAtomic.canonical), atomic.LoadUint64(&stateAtomic.droppedPipe))
		}
		if stop != nil {
			select {
			case <-stop:
				return nil
			default:
			}
		}
	}
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
		EventID:           atomic.AddUint64(&eventSequence, 1),
		TimestampMS:       uint64(now.UnixMilli()),
		MonotonicNS:       uint64(now.UnixNano()),
		Source:            SourceNpcapSensor,
		LayerID:           0, // 0=TCP path (see schema)
		EventType:         TypeForward,
		Severity:          0,
		PolicyAction:      ActionLogOnly,
		DefconImpact:      5, // neutral
		IsPipe:            0,
		EnforcementStatus: 0,
	}

	// --- network identity (5-tuple) ---
	if l3 := packet.NetworkLayer(); l3 != nil {
		switch net := l3.(type) {
		case *layers.IPv4:
			srcIP := net.SrcIP.To4()
			dstIP := net.DstIP.To4()
			if len(srcIP) == 4 {
				ev.SourceIP = binary.BigEndian.Uint32(srcIP)
			}
			if len(dstIP) == 4 {
				ev.DestIP = binary.BigEndian.Uint32(dstIP)
			}
			ev.Protocol = uint8(net.Protocol)
		case *layers.IPv6:
			// IPv6 identity: embed first 4 bytes of each address AND mark
			// ContextV6Truncated. The v1 wire has no IPv6 fields, so the
			// 32-bit identity is degraded by construction and must never be
			// confused with an IPv4 address downstream.
			srcIP := net.SrcIP.To16()
			dstIP := net.DstIP.To16()
			if len(srcIP) >= 4 {
				ev.SourceIP = binary.BigEndian.Uint32(srcIP[:4])
			}
			if len(dstIP) >= 4 {
				ev.DestIP = binary.BigEndian.Uint32(dstIP[:4])
			}
			// T2-V6-022b: retain the full addresses for v2 frames. The
			// queue/forensic identity stays first-4-bytes + bit2 (frozen
			// u32 path); the tail travels for forensics/display plumbing.
			if len(srcIP) == 16 {
				copy(ev.Src6[:], srcIP)
			}
			if len(dstIP) == 16 {
				copy(ev.Dst6[:], dstIP)
			}
			ev.ContextFlags |= ContextV6Truncated
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
			// RB-021-NOSE-FLAGS: carry the raw flags byte in the
			// ContextFlags transport lane. The byte layout matches the
			// direct Zig path's transport-header byte 13 (FIN..CWR), so
			// FLAGS:S / FLAGS:FPU predicates see the same evidence on
			// both acquisition paths.
			ev.SetTCPFlags(tcpFlagsByte(tr))
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

// tcpFlagsByte renders the TCP control bits in the same one-byte layout
// the packet header uses (FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08,
// ACK=0x10, URG=0x20, ECE=0x40, CWR=0x80). NS lives in the preceding
// byte and is intentionally not part of the L4 predicate vocabulary.
func tcpFlagsByte(tcp *layers.TCP) uint8 {
	var flags uint8
	if tcp.FIN {
		flags |= 0x01
	}
	if tcp.SYN {
		flags |= 0x02
	}
	if tcp.RST {
		flags |= 0x04
	}
	if tcp.PSH {
		flags |= 0x08
	}
	if tcp.ACK {
		flags |= 0x10
	}
	if tcp.URG {
		flags |= 0x20
	}
	if tcp.ECE {
		flags |= 0x40
	}
	if tcp.CWR {
		flags |= 0x80
	}
	return flags
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

// captureProbeRun intentionally stops before BPF filtering, packet decoding,
// CanonicalEvent serialization, and named-pipe delivery. It answers one
// question only: can this exact Npcap interface deliver raw frames?
func captureProbeRun(iface string, duration time.Duration) error {
	if iface == "" {
		name, err := firstUpDevice()
		if err != nil {
			return err
		}
		iface = name
	} else if err := validateCaptureInterface(iface); err != nil {
		return fmt.Errorf("nose probe: %w", err)
	}
	handle, err := pcap.OpenLive(iface, 65535, false, 500*time.Millisecond)
	if err != nil {
		return fmt.Errorf("open %s: %w", iface, err)
	}
	defer handle.Close()
	fmt.Fprintf(os.Stderr, "[NOSE PROBE] raw capture on %s for %s (no BPF, no pipe)\n", iface, duration)
	deadline := time.Now().Add(duration)
	packets := 0
	timeouts := 0
	for time.Now().Before(deadline) {
		data, _, readErr := handle.ReadPacketData()
		if readErr != nil {
			if strings.Contains(strings.ToLower(readErr.Error()), "timeout") {
				timeouts++
				continue
			}
			return fmt.Errorf("ReadPacketData after %d packets: %w", packets, readErr)
		}
		packets++
		if packets <= 3 {
			fmt.Fprintf(os.Stderr, "[NOSE PROBE] raw packet %d: %d bytes\n", packets, len(data))
		}
	}
	fmt.Fprintf(os.Stderr, "[NOSE PROBE] result: packets=%d timeouts=%d\n", packets, timeouts)
	return nil
}

func captureProbeAllRun(duration time.Duration) error {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return fmt.Errorf("FindAllDevs: %w", err)
	}
	for i, d := range devs {
		fmt.Fprintf(os.Stderr, "[NOSE PROBE-ALL] #%d begin name=%s description=%q\n", i, d.Name, d.Description)
		err := captureProbeRun(d.Name, duration)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[NOSE PROBE-ALL] #%d error=%v\n", i, err)
		}
	}
	return nil
}

// captureSelfTest validates the encoder end-to-end without needing a
// live consumer: one synthetic packet → wire bytes → sanity checks.
func captureSelfTest() error {
	fake := &CanonicalEvent{
		EventID:       1,
		TimestampMS:   1700000000000,
		MonotonicNS:   1700000000000000000,
		Source:        SourceNpcapSensor,
		SourceIP:      0xC0A80164, // 192.168.1.100
		SourcePort:    49152,
		DestIP:        0xAC1F0A0A,
		DestPort:      443,
		Protocol:      6,
		EventType:     TypeForward,
		Severity:      0,
		PolicyAction:  ActionLogOnly,
		DefconImpact:  5,
		PayloadLength: 40,
		PID:           1234,
		PPID:          5678,
		NodeID:        7,
		Confidence:    0,
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
	// T2-V6-022b: v6 synthetic exercises the emit path end to end
	// (eventFromPacket fills Src6/Dst6; Send dispatches to SerializeV2).
	v6src := net.ParseIP("2001:db8::1")
	v6dst := net.ParseIP("2001:db8::2")
	if v6src.To16() == nil || v6dst.To16() == nil {
		return fmt.Errorf("capture self-test: test host cannot parse IPv6 literals")
	}
	v6ev := &CanonicalEvent{
		Source:       SourceNpcapSensor,
		SourceIP:     binary.BigEndian.Uint32(v6src.To16()[:4]),
		DestIP:       binary.BigEndian.Uint32(v6dst.To16()[:4]),
		ContextFlags: ContextV6Truncated,
	}
	copy(v6ev.Src6[:], v6src.To16())
	copy(v6ev.Dst6[:], v6dst.To16())
	if !v6ev.IsV6() {
		return fmt.Errorf("capture self-test: IsV6 must hold with bit2 set")
	}
	v6wire, err := v6ev.SerializeV2()
	if err != nil {
		return fmt.Errorf("capture self-test: v2 serialize: %w", err)
	}
	if len(v6wire) != EventV2WireSize {
		return fmt.Errorf("capture self-test: v2 wire size %d != %d", len(v6wire), EventV2WireSize)
	}
	back, err := DeserializeDispatch(v6wire[:])
	if err != nil {
		return fmt.Errorf("capture self-test: v2 dispatch: %w", err)
	}
	if back.Src6 != v6ev.Src6 || back.Dst6 != v6ev.Dst6 {
		return fmt.Errorf("capture self-test: v2 full addresses differ after dispatch")
	}
	fmt.Printf("capture self-test OK: v2 %d bytes wire, full identity round-trips\n", len(v6wire))
	return nil
}
