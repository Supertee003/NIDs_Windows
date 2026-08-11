module github.com/aegis-nids/perf_go

go 1.22

// This module links against libaegis_shield (Rust) via cgo.
// Build: CGO_ENABLED=1 go build -o aegis_perf.exe
