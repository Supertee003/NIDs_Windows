//go:build !service

// console_main.go — console entrypoint (build tag `!service`).
// The Windows service wrapper lives in service_main.go (build tag `service`)
// and reuses runAggregator()/requestShutdown() from server_runtime.go.
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	// G27 Gate-A: --version flag. Print SEMVER + exit 0 before any
	// initialization so the supervisor (and tests/runtime/test_version.py)
	// can verify the binary is present and reports a parseable version.
	for _, arg := range os.Args[1:] {
		if arg == "--version" || arg == "-v" || arg == "-V" {
			fmt.Println("aegis-aggregator 0.1.0")
			os.Exit(0)
		}
	}

	log.Printf("[AGGREGATOR] console mode starting")
	runAggregator()

	// Wait for shutdown signal; runAggregator's HTTP server is bound by now
	// unless a startup error occurred (requestShutdown is a no-op then).
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Printf("[AGGREGATOR] Shutting down...")
	requestShutdown()
	log.Printf("[AGGREGATOR] Shutdown complete")
	_ = http.ErrServerClosed // referenced for symmetry with service variant
}
