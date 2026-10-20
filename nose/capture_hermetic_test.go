package main

// CAPTURE-096: hermetic pins for the Npcap decode path. eventFromPacket
// must decode identity from raw frames with no hardware: BE-numeric IPv4
// identity (matching the golden fixtures, e.g. 10.0.0.1 == 0x0A000001),
// ports, protocol, and sane defaults — and must never panic on garbage.
import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func decodeTestFrame(t *testing.T, raw []byte) gopacket.Packet {
	t.Helper()
	return gopacket.NewPacket(raw, layers.LayerTypeEthernet, gopacket.NoCopy)
}

func TestEventFromPacketIPv4Identity(t *testing.T) {
	raw := []byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x00,
		0x45, 0x00, 0x00, 0x36, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
		0x0a, 0x00, 0x00, 0x05, 0xc0, 0xa8, 0x01, 0x01,
		0x04, 0xd2, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x20, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
	ev := eventFromPacket(decodeTestFrame(t, raw))
	if ev == nil {
		t.Fatal("valid frame must produce an event")
	}
	if ev.SourceIP != 0x0A000005 {
		t.Fatalf("SourceIP = %#x, want 0x0A000005", ev.SourceIP)
	}
	if ev.DestIP != 0xC0A80101 {
		t.Fatalf("DestIP = %#x, want 0xC0A80101", ev.DestIP)
	}
	if ev.SourcePort != 1234 || ev.DestPort != 80 || ev.Protocol != 6 {
		t.Fatalf("ports/proto = %d/%d/%d, want 1234/80/6",
			ev.SourcePort, ev.DestPort, ev.Protocol)
	}
	if ev.Source != SourceNpcapSensor || ev.EventType != TypeForward {
		t.Fatalf("source/type = %d/%d, want sensor/forward", ev.Source, ev.EventType)
	}
	if ev.TimestampMS == 0 || ev.EventID == 0 {
		t.Fatal("timestamps and sequence must be populated")
	}
}

func TestEventFromPacketCarriesTCPFlagsLane(t *testing.T) {
	// RB-021-NOSE-FLAGS: the raw TCP flags byte must survive into the
	// ContextFlags transport lane so the Zig L4 matcher sees the same
	// evidence as the direct Npcap path. The frame below has SYN at TCP
	// header byte 13 (offset 34 + 13).
	raw := []byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x00,
		0x45, 0x00, 0x00, 0x36, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
		0x0a, 0x00, 0x00, 0x05, 0xc0, 0xa8, 0x01, 0x01,
		0x04, 0xd2, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x20, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
	ev := eventFromPacket(decodeTestFrame(t, raw))
	flags, ok := ev.TCPFlags()
	if !ok {
		t.Fatal("TCP flags lane must be valid for an observed TCP header")
	}
	if flags != 0x02 {
		t.Fatalf("TCP flags = %#x, want SYN 0x02", flags)
	}

	// The lane must survive the frozen v1 wire unchanged.
	wire, err := ev.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	var decoded CanonicalEvent
	if !decoded.Deserialize(wire) {
		t.Fatal("serialize output must deserialize")
	}
	flags, ok = decoded.TCPFlags()
	if !ok || flags != 0x02 {
		t.Fatalf("round-trip flags = %#x valid=%v, want SYN", flags, ok)
	}
}

func TestEventFromPacketXmasFlagsAndNonTCPAbsence(t *testing.T) {
	ip := &layers.IPv4{Version: 4, IHL: 5, SrcIP: []byte{192, 0, 2, 10}, DstIP: []byte{192, 0, 2, 20}, Protocol: layers.IPProtocolTCP}
	tcp := &layers.TCP{SrcPort: 40000, DstPort: 443, FIN: true, PSH: true, URG: true}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("checksum: %v", err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, ip, tcp); err != nil {
		t.Fatalf("serialize TCP: %v", err)
	}
	ev := eventFromPacket(gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.NoCopy))
	flags, ok := ev.TCPFlags()
	if !ok || flags != 0x29 {
		t.Fatalf("XMAS flags = %#x valid=%v, want 0x29", flags, ok)
	}

	// UDP is not TCP; the lane must stay absent, not a fake zero byte.
	udpIP := &layers.IPv4{Version: 4, IHL: 5, SrcIP: []byte{192, 0, 2, 10}, DstIP: []byte{192, 0, 2, 20}, Protocol: layers.IPProtocolUDP}
	udp := &layers.UDP{SrcPort: 40000, DstPort: 53}
	if err := udp.SetNetworkLayerForChecksum(udpIP); err != nil {
		t.Fatalf("UDP checksum: %v", err)
	}
	udpBuf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(udpBuf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, udpIP, udp); err != nil {
		t.Fatalf("serialize UDP: %v", err)
	}
	udpEvent := eventFromPacket(gopacket.NewPacket(udpBuf.Bytes(), layers.LayerTypeIPv4, gopacket.NoCopy))
	if _, ok := udpEvent.TCPFlags(); ok {
		t.Fatal("UDP must not claim TCP flag evidence")
	}
}

func TestEventFromPacketGarbageNeverPanics(t *testing.T) {
	for _, raw := range [][]byte{nil, {}, {0x00}, {0xff, 0xff}} {
		ev := eventFromPacket(decodeTestFrame(t, raw))
		if ev == nil {
			t.Fatal("garbage must yield a default event, never nil")
		}
		if ev.SourceIP != 0 || ev.DestIP != 0 {
			t.Fatalf("garbage must yield zero identity, got %#x/%#x", ev.SourceIP, ev.DestIP)
		}
	}
}
