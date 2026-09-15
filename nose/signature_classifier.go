package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/google/gopacket"
)

type noseSignatureRule struct {
	RuleID      string `json:"rule_id"`
	MatchPattern string `json:"match_pattern"`
	Severity    string `json:"severity"`
}

type noseRulesFile struct {
	Rules []noseSignatureRule `json:"nids_rules"`
}

var activeNoseSignatureRules []noseSignatureRule

func loadNoseSignatureRules() error {
	path := os.Getenv("AEGIS_RULES_PATH")
	if path == "" {
		path = "configs/Rules.json"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	var file noseRulesFile
	if err := json.Unmarshal(data, &file); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	activeNoseSignatureRules = file.Rules[:0]
	for _, rule := range file.Rules {
		if rule.RuleID != "" && rule.MatchPattern != "" {
			activeNoseSignatureRules = append(activeNoseSignatureRules, rule)
		}
	}
	fmt.Fprintf(os.Stderr, "[NOSE RULES] loaded=%d path=%s\n", len(activeNoseSignatureRules), path)
	return nil
}

func classifyNosePacket(ev *CanonicalEvent, packet gopacket.Packet) {
	application := packet.ApplicationLayer()
	if application == nil || len(activeNoseSignatureRules) == 0 {
		return
	}
	payload := application.Payload()
	for _, rule := range activeNoseSignatureRules {
		if !strings.Contains(string(payload), rule.MatchPattern) {
			continue
		}
		ev.EventType = TypeMatch
		ev.RuleID = hashNoseRuleID(rule.RuleID)
		ev.Severity = noseSeverityOrdinal(rule.Severity)
		return
	}
}

func hashNoseRuleID(value string) uint32 {
	var hash uint32 = 0x811c9dc5
	for i := 0; i < len(value); i++ {
		hash ^= uint32(value[i])
		hash *= 0x01000193
	}
	return hash
}

func noseSeverityOrdinal(value string) byte {
	switch strings.ToLower(value) {
	case "medium":
		return 1
	case "high":
		return 2
	case "critical":
		return 3
	default:
		return 0
	}
}
