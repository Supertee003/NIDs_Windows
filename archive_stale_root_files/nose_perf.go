package main

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"
)

var startTime = time.Now()

type PerfMetrics struct {
	mu         sync.Mutex
	CPUUsage   float64
	MemUsage   float64
	Goroutines int
	Uptime     time.Duration
}

var metrics PerfMetrics

func cpuMonitor(stop <-chan struct{}) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			metrics.mu.Lock()
			metrics.CPUUsage = float64(runtime.NumGoroutine()) / float64(runtime.NumCPU()) * 10.0
			if metrics.CPUUsage > 100.0 {
				metrics.CPUUsage = 100.0
			}
			metrics.Goroutines = runtime.NumGoroutine()
			metrics.Uptime = time.Since(startTime)
			metrics.mu.Unlock()
		}
	}
}

func memMonitor(stop <-chan struct{}) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	var m runtime.MemStats
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			runtime.ReadMemStats(&m)
			metrics.mu.Lock()
			metrics.MemUsage = float64(m.Alloc) / float64(m.Sys) * 100.0
			metrics.mu.Unlock()
		}
	}
}

func reporter(stop <-chan struct{}) {
	ticker := time.NewTicker(4 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			metrics.mu.Lock()
			fmt.Printf("[NOSE] CPU=%.1f%% Mem=%.1f%% Goroutines=%d Uptime=%v\n",
				metrics.CPUUsage, metrics.MemUsage, metrics.Goroutines, metrics.Uptime.Round(time.Second))
			metrics.mu.Unlock()
		}
	}
}

func main() {
	fmt.Println("============================================================")
	fmt.Println(" AEGIS NOSE - Performance Monitor")
	fmt.Printf(" Go %s | CPUs=%d | OS=%s\n", runtime.Version(), runtime.NumCPU(), runtime.GOOS)
	fmt.Println("============================================================")

	stop := make(chan struct{})
	var wg sync.WaitGroup

	monitors := []func(<-chan struct{}){cpuMonitor, memMonitor, reporter}
	for _, fn := range monitors {
		wg.Add(1)
		go func(f func(<-chan struct{})) {
			defer wg.Done()
			f(stop)
		}(fn)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	fmt.Println("[NOSE] Monitoring started - press Ctrl+C to stop")
	<-sigChan
	fmt.Println("\n[NOSE] Shutting down...")
	close(stop)
	wg.Wait()
	fmt.Println("[NOSE] Stopped.")
}
