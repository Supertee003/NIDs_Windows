// service_main.go — Windows service wrapper for aegis-aggregator (build tag: service)
//
//go:build service

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
)

type aegisService struct{}

func (m *aegisService) Execute(args []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	s <- svc.Status{State: svc.StartPending}

	logPath := filepath.Join("logs", "aggregator_service.log")
	_ = os.MkdirAll("logs", 0o755)
	lf, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return false, 1
	}
	defer lf.Close()
	log.SetOutput(lf)
	wd, _ := os.Getwd()
	log.Printf("[SERVICE] wrapper starting (args=%v cwd=%s)", args, wd)

	done := make(chan bool, 1)
	go func() {
		runAggregator()
		done <- true
	}()

	select {
	case <-time.After(2 * time.Second):
		s <- svc.Status{State: svc.Running, Accepts: accepted}
		log.Printf("[SERVICE] reported RUNNING to SCM")
	case <-done:
		s <- svc.Status{State: svc.Stopped}
		log.Printf("[SERVICE] aggregator exited during startup")
		return false, 1
	}

	for {
		select {
		case <-done:
			log.Printf("[SERVICE] aggregator main loop exited")
			s <- svc.Status{State: svc.StopPending}
			return false, 0
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				s <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				log.Printf("[SERVICE] stop requested")
				s <- svc.Status{State: svc.StopPending}
				requestShutdown()
				time.Sleep(2 * time.Second)
				s <- svc.Status{State: svc.Stopped}
				return false, 0
			default:
				log.Printf("[SERVICE] unexpected cmd=%d", c.Cmd)
			}
		}
	}
}

func main() {
	inService, err := svc.IsWindowsService()
	if err != nil {
		fmt.Fprintln(os.Stderr, "svc check failed:", err)
		os.Exit(2)
	}
	if !inService {
		fmt.Fprintln(os.Stderr, "aegis-aggregator-service wrapper - run via Windows service only")
		os.Exit(1)
	}
	if err := svc.Run("AegisAggregator", &aegisService{}); err != nil {
		errPath := filepath.Join(os.TempDir(), "aegis_aggregator_svc_err.log")
		lf, ferr := os.OpenFile(errPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if ferr == nil {
			fmt.Fprintf(lf, "%s svc.Run: %v\n", time.Now().Format(time.RFC3339), err)
			lf.Close()
		}
		os.Exit(1)
	}
}
