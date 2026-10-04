//! golden_path_ffi.go - Cross-language golden vector validation
//!
//! Proves that Go can read the same .bin golden vector fixtures and produce
//! identical semantic output as Zig, C++, Python, and Rust.
//!
//! Evidence level: E3 (component integration across language runtimes)

package main

import (
	"strconv"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// vectorsDir locates the committed fixtures. go test runs with cwd=nose/,
// so fixtures live one level up (NOT under nose/tests/, which does not
// exist â€” the old "tests/contracts/..." prefix could never resolve).
func vectorsDir() string {
	return filepath.Join("..", "tests", "contracts", "event_vectors", "event_vectors")
}

// sharedGoldenVectors loads the canonical golden vector definitions from JSON.
func sharedGoldenVectors() (map[string]map[string]interface{}, error) {
	// Walk to the test vectors directory
	dir, err := os.ReadDir(vectorsDir())
	if err != nil {
		return nil, err
	}

	vectors := make(map[string]map[string]interface{})
	for _, d := range dir {
		if strings.HasSuffix(d.Name(), ".bin") {
			// Read the corresponding metadata from golden_vectors.json
			data, err := os.ReadFile(filepath.Join(vectorsDir(), "golden_vectors.json"))
			if err != nil {
				return nil, err
			}
			var meta map[string]interface{}
			json.Unmarshal(data, &meta)
			if v, ok := meta["vectors"].(map[string]interface{})[d.Name()]; ok {
				obj, ok := v.(map[string]interface{})
				if !ok {
					continue
				}
				fields, _ := obj["fields"].(map[string]interface{})
					vectors[d.Name()] = fields
				}
		}
	}
	return vectors, nil
}

// goldenVectorFields extracts the expected field values for a given vector name
// from the golden_vectors.json metadata.
func goldenVectorFields(name string) (map[string]interface{}, error) {
	data, err := os.ReadFile(filepath.Join(vectorsDir(), "golden_vectors.json"))
	if err != nil {
		return nil, err
	}
	// UseNumber: payload_hash exceeds float64 exact range; the literal
	// must survive decoding bit-exact for the comparison below.
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.UseNumber()
	var meta struct {
		Vectors map[string]struct {
			Fields map[string]interface{} `json:"fields"`
		} `json:"vectors"`
	}
	if err := dec.Decode(&meta); err != nil {
		return nil, err
	}
	if v, ok := meta.Vectors[name]; ok {
		return v.Fields, nil
	}
	return nil, fmt.Errorf("vector %s not found in golden_vectors.json", name)
}

// Deserialize decodes a 109-byte wire format event from raw bytes.
func Deserialize(b []byte) (*CanonicalEvent, error) {
	if len(b) != EventWireSize {
		return nil, fmt.Errorf("wire format: expected %d bytes, got %d", EventWireSize, len(b))
	}
	// The first eight bytes are the frozen wire header:
	// magic (u32), schema version (u16), and struct-size marker (u16).
	// EventID starts at offset 8; treating b[0:8] as EventID silently
	// converts a valid frame into a different semantic event.
	if binary.LittleEndian.Uint32(b[0:4]) != EventMagic {
		return nil, fmt.Errorf("wire format: invalid magic 0x%08x", binary.LittleEndian.Uint32(b[0:4]))
	}
	if binary.LittleEndian.Uint16(b[4:6]) != EventSchemaVersion {
		return nil, fmt.Errorf("wire format: unsupported schema %d", binary.LittleEndian.Uint16(b[4:6]))
	}
	// Strict like production: struct_size is the sender in-memory layout
	// tag (128). The frozen v1 vectors stamp 128 like every live producer.
	if binary.LittleEndian.Uint16(b[6:8]) != DefaultDevStructSize {
		return nil, fmt.Errorf("wire format: unexpected struct size %d", binary.LittleEndian.Uint16(b[6:8]))
	}
	// VOL04-NOSE-001: same enum/confidence gates as CanonicalEvent.Deserialize
	// (canonical.go) and Zig deserializeFromBytes â€” the FFI path must not
	// accept frames the runtime spine would reject.
	if !validSource(b[32]) {
		return nil, fmt.Errorf("wire format: unknown source %d", b[32])
	}
	if !validEventType(binary.LittleEndian.Uint32(b[57:61])) {
		return nil, fmt.Errorf("wire format: unknown event_type %d", binary.LittleEndian.Uint32(b[57:61]))
	}
	if !validPolicyAction(b[86]) {
		return nil, fmt.Errorf("wire format: unknown policy_action %d", b[86])
	}
	if b[93+ResOffConfidence] > 100 {
		return nil, fmt.Errorf("wire format: confidence must be 0-100")
	}
	var e CanonicalEvent
	e.EventID = binary.LittleEndian.Uint64(b[8:16])
	e.TimestampMS = binary.LittleEndian.Uint64(b[16:24])
	e.MonotonicNS = binary.LittleEndian.Uint64(b[24:32])
	e.Source = b[32]
	e.SourceIP = binary.LittleEndian.Uint32(b[33:37])
	e.SourcePort = binary.LittleEndian.Uint16(b[37:39])
	e.DestIP = binary.LittleEndian.Uint32(b[39:43])
	e.DestPort = binary.LittleEndian.Uint16(b[43:45])
	e.SessionID = binary.LittleEndian.Uint64(b[45:53])
	e.Protocol = b[53]
	e.Direction = b[54]
	e.LayerID = b[55]
	e.IsPipe = b[56]
	e.EventType = binary.LittleEndian.Uint32(b[57:61])
	e.Severity = b[61]
	e.RuleID = binary.LittleEndian.Uint32(b[62:66])
	e.RulesetVersion = binary.LittleEndian.Uint64(b[66:74])
	e.PayloadLength = binary.LittleEndian.Uint32(b[74:78])
	e.PayloadHash = binary.LittleEndian.Uint64(b[78:86])
	e.PolicyAction = b[86]
	e.EnforcementStatus = b[87]
	e.DefconImpact = b[88]
	e.ContextFlags = binary.LittleEndian.Uint32(b[89:93])
	e.PID = binary.LittleEndian.Uint32(b[93 : 93+ResOffPid+4])
	e.PPID = binary.LittleEndian.Uint32(b[93+ResOffPpid:93+ResOffPpid+4])
	e.ProcType = b[93+ResOffProcType]
	e.Integrity = b[93+ResOffIntegrity]
	e.HidsFlag = b[93+ResOffHidsFlag]
	e.NodeID = binary.LittleEndian.Uint32(b[93+ResOffNodeID:93+ResOffNodeID+4])
	e.Confidence = b[93+ResOffConfidence]
	return &e, nil
}

// validateVectorFields compares parsed event fields against the golden vector definition.
func validateVectorFields(event *CanonicalEvent, expectedFields map[string]interface{}) bool {
	ok := true

	// Map expected field names to event fields. Comparison is canonical
	// uint64 on both sides: JSON carries hex strings ("0x.."), dotted IPs
	// and (via UseNumber) exact decimals beyond float64 range, while the
	// event holds raw integers. Anything unparseable fails loudly.
	toU64 := func(name string, v interface{}) (uint64, error) {
		switch t := v.(type) {
		case json.Number:
			return strconv.ParseUint(string(t), 10, 64)
		case float64:
			return uint64(t), nil
		case string:
			if strings.Contains(t, ".") && strings.Count(t, ".") == 3 {
				parts := strings.Split(t, ".")
				if len(parts) != 4 {
					return 0, fmt.Errorf("bad ip %q", t)
				}
				var ip uint64
				for _, p := range parts {
					n, err := strconv.ParseUint(p, 10, 8)
					if err != nil {
						return 0, err
					}
					ip = (ip << 8) | n
				}
				return ip, nil
			}
			return strconv.ParseUint(t, 0, 64)
		case bool:
			if t {
				return 1, nil
			}
			return 0, nil
		}
		return 0, fmt.Errorf("uncomparable %s (%T)", name, v)
	}
	checkField := func(name, label string, expected interface{}) {
		// Human annotations (descriptions, names, _hex duplicates) carry
		// no wire value; magic/version/struct_size are gate-checked at
		// decode time, not field-compared.
		if strings.HasSuffix(name, "_hex") || strings.HasSuffix(name, "_name") {
			return
		}
		switch name {
		case "description", "source_name", "magic", "version", "struct_size":
			return
		}
		var actual uint64
		var haveActual bool = true
		switch name {
		case "event_id":
			actual = event.EventID
		case "timestamp_ms":
			actual = event.TimestampMS
		case "monotonic_ns":
			actual = event.MonotonicNS
		case "source":
			actual = uint64(event.Source)
		case "source_ip":
			actual = uint64(event.SourceIP)
		case "source_port":
			actual = uint64(event.SourcePort)
		case "dest_ip":
			actual = uint64(event.DestIP)
		case "dest_port":
			actual = uint64(event.DestPort)
		case "session_id":
			actual = event.SessionID
		case "protocol":
			actual = uint64(event.Protocol)
		case "direction":
			actual = uint64(event.Direction)
		case "layer_id":
			actual = uint64(event.LayerID)
		case "is_pipe":
			actual = uint64(event.IsPipe)
		case "event_type":
			actual = uint64(event.EventType)
		case "severity":
			actual = uint64(event.Severity)
		case "rule_id":
			actual = uint64(event.RuleID)
		case "ruleset_version":
			actual = event.RulesetVersion
		case "payload_length":
			actual = uint64(event.PayloadLength)
		case "payload_hash":
			actual = event.PayloadHash
		case "policy_action":
			actual = uint64(event.PolicyAction)
		case "enforcement_status":
			actual = uint64(event.EnforcementStatus)
		case "defcon_impact":
			actual = uint64(event.DefconImpact)
		case "context_flags":
			actual = uint64(event.ContextFlags)
		case "pid":
			actual = uint64(event.PID)
		case "ppid":
			actual = uint64(event.PPID)
		case "proc_type":
			actual = uint64(event.ProcType)
		case "integrity":
			actual = uint64(event.Integrity)
		case "hids_flag":
			actual = uint64(event.HidsFlag)
		case "node_id":
			actual = uint64(event.NodeID)
		case "confidence":
			actual = uint64(event.Confidence)
		default:
			haveActual = false
		}
		if !haveActual {
			fmt.Printf("  UNKNOWN field %s: no event mapping\n", label)
			ok = false
			return
		}

		want, err := toU64(name, expected)
		if err != nil {
			fmt.Printf("  MISMATCH %s: uncomparable expected %v (%v)\n", label, expected, err)
			ok = false
			return
		}
		if actual != want {
			fmt.Printf("  MISMATCH %s: got %d (0x%x), expected %d\n", label, actual, actual, want)
			ok = false
		}
	}

	// Check all fields listed in the golden vector
	for name := range expectedFields {
		checkField(name, name, expectedFields[name])
	}

	return ok
}

// ============================================================================
// Tests
// ============================================================================

// TestGoldenVector cross-language: loads the shared .bin fixture and validates
// every field against the canonical definition in golden_vectors.json.
func ValidateGoldenVector() bool {
	// Load vector #001: Benign forward event
	expectedFields, err := goldenVectorFields("event_v1_001.bin")
	if err != nil {
		fmt.Printf("FAIL: Could not load golden vector metadata: %v\n", err)
		return false
	}

	// Read the binary fixture
	data, err := os.ReadFile(filepath.Join(vectorsDir(), "event_v1_001.bin"))
	if err != nil {
		fmt.Printf("FAIL: Could not read golden vector binary: %v\n", err)
		return false
	}

	// Deserialize
	event, err := Deserialize(data)
	if err != nil {
		fmt.Printf("FAIL: Could not deserialize golden vector: %v\n", err)
		return false
	}

	// Validate against expected fields
	if !validateVectorFields(event, expectedFields) {
		fmt.Printf("FAIL: event_v1_001.bin field validation failed\n")
		return false
	}
	fmt.Println("PASS: event_v1_001.bin - all fields validated (Go cross-language)")
	return true
}

// TestGoldenVector002 validates vector #002: APT block event.
func ValidateGoldenVector002() bool {
	expectedFields, err := goldenVectorFields("event_v1_002.bin")
	if err != nil {
		fmt.Printf("FAIL: Could not load golden vector metadata: %v\n", err)
		return false
	}

	data, err := os.ReadFile(filepath.Join(vectorsDir(), "event_v1_002.bin"))
	if err != nil {
		fmt.Printf("FAIL: Could not read golden vector binary: %v\n", err)
		return false
	}

	event, err := Deserialize(data)
	if err != nil {
		fmt.Printf("FAIL: Could not deserialize golden vector: %v\n", err)
		return false
	}

	if !validateVectorFields(event, expectedFields) {
		fmt.Printf("FAIL: event_v1_002.bin field validation failed\n")
		return false
	}
	fmt.Println("PASS: event_v1_002.bin - all fields validated (Go cross-language)")
	return true
}

// TestGoldenVector003 validates vector #003: Host event (process start).
func ValidateGoldenVector003() bool {
	expectedFields, err := goldenVectorFields("event_v1_003.bin")
	if err != nil {
		fmt.Printf("FAIL: Could not load golden vector metadata: %v\n", err)
		return false
	}

	data, err := os.ReadFile(filepath.Join(vectorsDir(), "event_v1_003.bin"))
	if err != nil {
		fmt.Printf("FAIL: Could not read golden vector binary: %v\n", err)
		return false
	}

	event, err := Deserialize(data)
	if err != nil {
		fmt.Printf("FAIL: Could not deserialize golden vector: %v\n", err)
		return false
	}

	if !validateVectorFields(event, expectedFields) {
		fmt.Printf("FAIL: event_v1_003.bin field validation failed\n")
		return false
	}
	fmt.Println("PASS: event_v1_003.bin - all fields validated (Go cross-language)")
	return true
}

// TestSemanticEquivalence is a cross-language conceptual test: it verifies that
// Go can read the same binary fixture that Zig, Python, C++, and Rust also read,
// and produce identical semantic field values. The actual per-language test
// implementations are in:
//   - Zig: src/tests/integration/golden_path_ffi.zig
//   - Python: shared/wire/wire_codec.py round-trip test
//   - C++: (pending - canonical_event_v1.h binary read)
//   - Rust: (TBD - canonical_event.rs implementation)
func ValidateSemanticEquivalence() bool {
	// Verify vector #001 round-trips correctly in Go
	ok := ValidateGoldenVector()
	// Verify vector #002
	ok = ValidateGoldenVector002() && ok
	// Verify vector #003
	ok = ValidateGoldenVector003() && ok
	if !ok {
		fmt.Println("FAIL: TestSemanticEquivalence - a vector failed validation")
		return false
	}
	fmt.Println("PASS: TestSemanticEquivalence - Go read+validate all 3 vectors")
	return true
}
