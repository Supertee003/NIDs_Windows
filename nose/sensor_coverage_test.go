package main

// AEGIS-008: hermetic sensor-coverage pins. These tests exercise the Go
// decode path with in-memory gopacket frames only. They are E2 evidence for
// decode/envelope framing, NOT host visibility proof for Npcap adapters,
// VLAN/QinQ on the wire, or IPv6 extension chains on a live interface.
import (
	"bytes"
	"hash/crc32"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func serializeHermeticFrame(t *testing.T, ls ...gopacket.SerializableLayer) []byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ls...); err != nil {
		t.Fatalf("serialize hermetic frame: %v", err)
	}
	return buf.Bytes()
}

func hermeticIPv4TCP() (*layers.IPv4, *layers.TCP) {
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.IPv4(10, 0, 0, 7),
		DstIP:    net.IPv4(10, 0, 0, 8),
	}
	tcp := &layers.TCP{SrcPort: 1512, DstPort: 443, SYN: true}
	_ = tcp.SetNetworkLayerForChecksum(ip)
	return ip, tcp
}

func assertHermeticIPv4Identity(t *testing.T, ev *CanonicalEvent) {
	t.Helper()
	if ev == nil {
		t.Fatal("tagged frame must produce an event")
	}
	if ev.SourceIP != 0x0A000007 || ev.DestIP != 0x0A000008 {
		t.Fatalf("identity = %#x/%#x, want 10.0.0.7/10.0.0.8", ev.SourceIP, ev.DestIP)
	}
	if ev.SourcePort != 1512 || ev.DestPort != 443 || ev.Protocol != 6 {
		t.Fatalf("5-tuple tail = %d/%d/%d, want 1512/443/6",
			ev.SourcePort, ev.DestPort, ev.Protocol)
	}
	if ev.Source != SourceNpcapSensor || ev.EventType != TypeForward {
		t.Fatalf("source/type = %d/%d, want sensor/forward", ev.Source, ev.EventType)
	}
	flags, ok := ev.TCPFlags()
	if !ok || flags != 0x02 {
		t.Fatalf("TCP flags = %#x valid=%v, want SYN", flags, ok)
	}
	// VLAN tags must not change the frozen 109-byte wire layout.
	wire, err := ev.Serialize()
	if err != nil {
		t.Fatalf("serialize tagged event: %v", err)
	}
	if len(wire) != EventWireSize {
		t.Fatalf("tagged v1 wire = %d bytes, want %d", len(wire), EventWireSize)
	}
	var decoded CanonicalEvent
	if !decoded.Deserialize(wire) {
		t.Fatal("tagged v1 wire must round-trip")
	}
	if decoded.SourceIP != ev.SourceIP || decoded.DestIP != ev.DestIP ||
		decoded.SourcePort != ev.SourcePort || decoded.DestPort != ev.DestPort {
		t.Fatalf("tagged round-trip lost identity: %+v", decoded)
	}
}

func TestEventFromPacketDecodesSingleVLANFrame(t *testing.T) {
	ip, tcp := hermeticIPv4TCP()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeDot1Q,
	}
	vlan := &layers.Dot1Q{VLANIdentifier: 42, Type: layers.EthernetTypeIPv4}
	raw := serializeHermeticFrame(t, eth, vlan, ip, tcp)
	pkt := gopacket.NewPacket(raw, layers.LayerTypeEthernet, gopacket.NoCopy)

	vlanLayers := 0
	for _, layer := range pkt.Layers() {
		if layer.LayerType() == layers.LayerTypeDot1Q {
			vlanLayers++
		}
	}
	if vlanLayers != 1 {
		t.Fatalf("single-tag packet exposed %d Dot1Q layers, want 1", vlanLayers)
	}
	assertHermeticIPv4Identity(t, eventFromPacket(pkt))
}

// gopacket v1.1.19 registers 0x8100 as Dot1Q but has no decoder registered
// for 0x88a8. Stacked 0x8100 tags are therefore the hermetic QinQ variant
// exercised here. This does not promote 0x88a8 service-tag host visibility.
func TestEventFromPacketDecodesStackedDot1QFrame(t *testing.T) {
	ip, tcp := hermeticIPv4TCP()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeDot1Q,
	}
	outer := &layers.Dot1Q{VLANIdentifier: 100, Type: layers.EthernetTypeDot1Q}
	inner := &layers.Dot1Q{VLANIdentifier: 200, Type: layers.EthernetTypeIPv4}
	raw := serializeHermeticFrame(t, eth, outer, inner, ip, tcp)
	pkt := gopacket.NewPacket(raw, layers.LayerTypeEthernet, gopacket.NoCopy)

	vlanLayers := 0
	for _, layer := range pkt.Layers() {
		if layer.LayerType() == layers.LayerTypeDot1Q {
			vlanLayers++
		}
	}
	if vlanLayers != 2 {
		t.Fatalf("stacked-tag packet exposed %d Dot1Q layers, want 2", vlanLayers)
	}
	assertHermeticIPv4Identity(t, eventFromPacket(pkt))
}

func TestEventFromPacketDecodesIPv6HopByHopTerminatingInTCP(t *testing.T) {
	ip := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolIPv6HopByHop,
		HopLimit:   64,
		SrcIP:      net.ParseIP("2001:db8::1"),
		DstIP:      net.ParseIP("2001:db9::2"),
	}
	hop := &layers.IPv6HopByHop{}
	hop.NextHeader = layers.IPProtocolTCP
	hop.Options = []*layers.IPv6HopByHopOption{{
		OptionType: 0x01, // PadN, four bytes => 8-byte extension header.
		OptionData: []byte{0, 0, 0, 0},
	}}
	ip.HopByHop = hop
	tcp := &layers.TCP{SrcPort: 4242, DstPort: 8443, ACK: true}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("IPv6 TCP checksum: %v", err)
	}
	raw := serializeHermeticFrame(t, ip, tcp)
	pkt := gopacket.NewPacket(raw, layers.LayerTypeIPv6, gopacket.NoCopy)

	if pkt.Layer(layers.LayerTypeIPv6HopByHop) == nil {
		t.Fatal("hop-by-hop extension layer missing from decoded packet")
	}
	ev := eventFromPacket(pkt)
	if ev == nil {
		t.Fatal("ext-chain frame must produce an event")
	}
	// The frozen u32 identity is the first four bytes plus ContextV6Truncated;
	// the transport layer resolves the chain to TCP and overrides Protocol.
	if ev.SourceIP != 0x20010DB8 || ev.DestIP != 0x20010DB9 {
		t.Fatalf("v6 identity = %#x/%#x, want 20010DB8/20010DB9", ev.SourceIP, ev.DestIP)
	}
	if ev.ContextFlags&ContextV6Truncated == 0 {
		t.Fatal("ext-chain event must carry ContextV6Truncated")
	}
	if ev.Protocol != 6 || ev.SourcePort != 4242 || ev.DestPort != 8443 {
		t.Fatalf("resolved 5-tuple = %d/%d/%d, want 6/4242/8443",
			ev.Protocol, ev.SourcePort, ev.DestPort)
	}
	flags, ok := ev.TCPFlags()
	if !ok || flags != 0x10 {
		t.Fatalf("ext-chain TCP flags = %#x valid=%v, want ACK", flags, ok)
	}
	wire, err := ev.SerializeV2()
	if err != nil {
		t.Fatalf("v6 ext-chain v2 serialize: %v", err)
	}
	if len(wire) != EventV2WireSize {
		t.Fatalf("v2 wire = %d bytes, want %d", len(wire), EventV2WireSize)
	}
	decoded, err := DeserializeDispatch(wire[:])
	if err != nil || decoded == nil {
		t.Fatalf("v2 ext-chain wire must round-trip: %v", err)
	}
	if !bytes.Equal(decoded.Src6[:], net.ParseIP("2001:db8::1").To16()) ||
		!bytes.Equal(decoded.Dst6[:], net.ParseIP("2001:db9::2").To16()) {
		t.Fatal("v2 ext-chain round-trip lost full IPv6 addresses")
	}
}

func TestCaptureAttachmentTaggedFrameCompleteness(t *testing.T) {
	ip, tcp := hermeticIPv4TCP()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeDot1Q,
	}
	vlan := &layers.Dot1Q{VLANIdentifier: 42, Type: layers.EthernetTypeIPv4}
	raw := serializeHermeticFrame(t, eth, vlan, ip, tcp)
	prov := captureProvenance{epoch: 71, generation: 3, interfaceID: 0x1234}

	payload, env := captureAttachment(raw, gopacket.CaptureInfo{
		CaptureLength: len(raw),
		Length:        len(raw),
	}, 11, prov)
	if env.Completeness != PayloadComplete || env.OriginalLen != uint16(len(raw)) {
		t.Fatalf("exact tagged capture envelope: %+v", env)
	}
	if len(payload) != len(raw) || env.PayloadLen != uint16(len(raw)) {
		t.Fatalf("exact tagged capture payload len = %d env=%+v", len(payload), env)
	}
	if env.PayloadCRC32 != crc32.ChecksumIEEE(raw) {
		t.Fatal("exact tagged capture CRC does not cover the frame")
	}

	const captured = 20
	payload, env = captureAttachment(raw[:captured], gopacket.CaptureInfo{
		CaptureLength: captured,
		Length:        len(raw),
	}, 12, prov)
	if env.Completeness != PayloadTruncated || env.OriginalLen != uint16(len(raw)) {
		t.Fatalf("snaplen-truncated tagged capture envelope: %+v", env)
	}
	if len(payload) != captured || env.PayloadLen != captured {
		t.Fatalf("snaplen payload len = %d env=%+v", len(payload), env)
	}
	if env.PayloadCRC32 != crc32.ChecksumIEEE(raw[:captured]) {
		t.Fatal("snaplen CRC must cover only captured bytes")
	}
}
