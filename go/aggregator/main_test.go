package main

import (
	"strings"
	"testing"
)

// GO-LOOPBACK-031: the aggregator REST API must stay loopback-only.
// The documented contract is 127.0.0.1:9200 and every in-tree client uses
// loopback; a bare ":port" bind would expose alerts + purge to the LAN.
func TestAPIAddrIsLoopbackOnly(t *testing.T) {
	addr := apiAddr(9200)
	if addr != "127.0.0.1:9200" {
		t.Errorf("apiAddr(9200) = %q, want %q", addr, "127.0.0.1:9200")
	}
	if strings.HasPrefix(addr, ":") {
		t.Errorf("apiAddr must never be a wildcard bind, got %q", addr)
	}
	if strings.Contains(addr, "0.0.0.0") {
		t.Errorf("apiAddr must never bind all interfaces, got %q", addr)
	}
}

func TestAPIAddrRespectsPort(t *testing.T) {
	if got := apiAddr(9300); got != "127.0.0.1:9300" {
		t.Errorf("apiAddr(9300) = %q, want %q", got, "127.0.0.1:9300")
	}
}
