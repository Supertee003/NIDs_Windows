//go:build go1.20

package main

import "github.com/google/uuid"

// generateUUID creates a new UUID string.
// Shared by both build variants (console main.go and the windows-service
// wrapper service_main.go) — alert.go/AddAlert calls it under either tag.
func generateUUID() string {
	return uuid.New().String()
}
