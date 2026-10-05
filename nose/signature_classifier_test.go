package main

import (
	"net"
	"path/filepath"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// DETECTION-CONTRACT-PIN-001: the Go network classifier and the Zig detector
// must agree on one rule set, one rule-id space and one matching field.
//
// Both tiers read configs/Rules.json, hash the rule_id string with FNV-1a and
// match the `match_pattern` field (substring, case-sensitive). The regex
// patterns in the same file belong to the Python Brain path only.
//
// These golden values are computed independently in Python by
// tests/security/test_detection_contract_pin.py and asserted again by the Zig
// unit test in src/pipeline/rule_loader.zig, so no tier can silently change
// the rule-id space on its own.
var goldenRuleHashes = map[string]uint32{
	"R0056": 2107512682,
	"R0088": 4254503461,
	"R0089": 4237725842,
	"R1001": 3813986375,
	"R1002": 3830763994,
	"R1003": 3847541613,
	"R1004": 3730098280,
	"R1005": 3746875899,
	"R2001": 2452150132,
	"R2002": 2502482989,
	"R2003": 2485705370,
	"R2004": 2401817275,
	"R2005": 2385039656,
	"R3001": 1836645033,
	"R3002": 1786312176,
	"R3003": 1803089795,
	"R3004": 1886977890,
	"R3005": 1903755509,
	"R9002": 1812566754,
	"R9006": 1745456278,
	"R9007": 1762233897,
	"R9059": 4009890390,
	"R9064": 4194591294,
}

func TestRuleHashesMatchTheSharedGoldenTable(t *testing.T) {
	t.Setenv("AEGIS_RULES_PATH", filepath.Join("..", "configs", "Rules.json"))
	if err := loadNoseSignatureRules(); err != nil {
		t.Fatalf("loadNoseSignatureRules: %v", err)
	}
	if len(activeNoseSignatureRules) != len(goldenRuleHashes) {
		t.Fatalf("loaded %d rules, golden table holds %d",
			len(activeNoseSignatureRules), len(goldenRuleHashes))
	}
	for _, rule := range activeNoseSignatureRules {
		want, ok := goldenRuleHashes[rule.RuleID]
		if !ok {
			t.Fatalf("rule %s is not in the golden table", rule.RuleID)
		}
		if got := hashNoseRuleID(rule.RuleID); got != want {
			t.Errorf("hashNoseRuleID(%s) = %d, golden %d", rule.RuleID, got, want)
		}
	}
}

func TestClassifierMatchesOnlyTheMatchPattern(t *testing.T) {
	defer func(previous []noseSignatureRule) { activeNoseSignatureRules = previous }(activeNoseSignatureRules)
	activeNoseSignatureRules = []noseSignatureRule{
		{RuleID: "R0056", MatchPattern: "' OR 1=1", Severity: "Critical"},
	}

	matched := &CanonicalEvent{}
	classifyNosePacket(matched, buildTCPPacket(t, []byte("GET /login?id=' OR 1=1-- HTTP/1.1\r\n\r\n")))
	if matched.EventType != TypeMatch {
		t.Fatalf("match_pattern substring must produce a match, got event type %d", matched.EventType)
	}
	if matched.RuleID != hashNoseRuleID("R0056") {
		t.Fatalf("rule attribution = %d, want %d", matched.RuleID, hashNoseRuleID("R0056"))
	}
	if matched.Severity != noseSeverityOrdinal("Critical") {
		t.Fatalf("severity ordinal = %d", matched.Severity)
	}

	// The regex_pattern is owned by the Python Brain: a payload that only the
	// regex would match must NOT match the Go substring classifier, otherwise
	// two engines would claim the same detection with different semantics.
	regexOnly := &CanonicalEvent{}
	classifyNosePacket(regexOnly, buildTCPPacket(t, []byte("marker INFO:SQLI_BYPASS only")))
	if regexOnly.EventType == TypeMatch {
		t.Fatalf("regex-only marker must not match the substring classifier")
	}
}

func buildTCPPacket(t *testing.T, payload []byte) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.IP{10, 0, 0, 1},
		DstIP:    net.IP{10, 0, 0, 2},
	}
	tcp := &layers.TCP{SrcPort: 40000, DstPort: 80, Seq: 1, DataOffset: 5}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("SetNetworkLayerForChecksum: %v", err)
	}
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buffer, options, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("SerializeLayers: %v", err)
	}
	return gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}
