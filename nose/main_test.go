package main

import (
	"os"
	"testing"
)

func TestPublishCaptureInterfacePublishesExactSelector(t *testing.T) {
	const selector = `\Device\NPF_{CE375996-106D-46F7-A67C-0168EAE8C96F}`
	previous, hadPrevious := os.LookupEnv(noseIfaceEnv)
	t.Cleanup(func() {
		if hadPrevious {
			_ = os.Setenv(noseIfaceEnv, previous)
		} else {
			_ = os.Unsetenv(noseIfaceEnv)
		}
	})

	if err := publishCaptureInterface("  " + selector + "  "); err != nil {
		t.Fatalf("publishCaptureInterface() error = %v", err)
	}
	if got := os.Getenv(noseIfaceEnv); got != selector {
		t.Fatalf("%s = %q, want %q", noseIfaceEnv, got, selector)
	}
}

func TestPublishCaptureInterfaceClearsAutoSelectedValue(t *testing.T) {
	if err := os.Setenv(noseIfaceEnv, "stale-selector"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Unsetenv(noseIfaceEnv) })

	if err := publishCaptureInterface(""); err != nil {
		t.Fatalf("publishCaptureInterface() error = %v", err)
	}
	if _, ok := os.LookupEnv(noseIfaceEnv); ok {
		t.Fatalf("%s remained set after auto-selection", noseIfaceEnv)
	}
}
