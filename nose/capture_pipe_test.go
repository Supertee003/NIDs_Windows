//go:build windows

// CAP-E2E-177: capture-to-pipe golden path on a live adapter.
//
// Spins a test named-pipe server, runs runCapture against the
// auto-selected adapter, and validates that length-prefixed wire frames
// arriving on the pipe decode as CanonicalEvents. Needs Npcap plus live
// traffic; skips (never fails) when the air is quiet or Npcap is absent,
// because an empty capture proves nothing about the pipeline.
package main

import (
        "encoding/binary"
        "fmt"
        "os"
        "sync"
        "testing"
        "time"

        "golang.org/x/sys/windows"
)

func TestCapturePipeDeliversCanonicalEvents(t *testing.T) {
        // Skip (never fail) without Npcap: an absent capture device is an
        // environmental fact, not a pipeline defect. The iface is resolved
        // once and passed explicitly so the test never sniffs a different
        // device than the one proven present.
        iface, err := firstUpDevice()
        if err != nil {
                t.Skipf("no Npcap capture device: %v", err)
        }
        pipeName := fmt.Sprintf(`\\.\pipe\aegis_nose_e2e_%d`, os.Getpid())
        namePtr, err := windows.UTF16PtrFromString(pipeName)
        if err != nil {
                t.Fatalf("pipe name: %v", err)
        }
        handle, err := windows.CreateNamedPipe(namePtr,
                windows.PIPE_ACCESS_INBOUND,
                windows.PIPE_TYPE_MESSAGE|windows.PIPE_READMODE_MESSAGE|windows.PIPE_WAIT,
                1, 65536, 65536, 0, nil)
        if err != nil {
                t.Fatalf("pipe create: %v", err)
        }
        // Lifetime rule: pipeFile owns the handle from here on (Go runtime
        // poller integration). Teardown closes pipeFile (never raw
        // CloseHandle: that deadlocks against a pending runtime-polled
        // Read); the deferred Close below is a backstop for early exits
        // and is a harmless no-op on the normal path.
        pipeFile := os.NewFile(uintptr(handle), pipeName)
        defer pipeFile.Close()

        connected := make(chan struct{})
        go func() {
                // Blocks until the capture client dials (or errors when the
                // handle closes during teardown).
                _ = windows.ConnectNamedPipe(handle, nil)
                close(connected)
        }()

        var mu sync.Mutex
        var frames [][]byte
        readerDone := make(chan struct{})
        go func() {
                defer close(readerDone)
                for {
                        buf := make([]byte, 65536)
                        n, rerr := pipeFile.Read(buf)
                        if rerr != nil || n <= 0 {
                                return
                        }
                        mu.Lock()
                        frames = append(frames, append([]byte(nil), buf[:n]...))
                        mu.Unlock()
                }
        }()

        stop := make(chan struct{})
        capDone := make(chan error, 1)
        go func() {
                capDone <- runCapture(iface, pipeName, stop)
        }()

        select {
        case <-connected:
        case <-time.After(15 * time.Second):
                close(stop)
                t.Fatal("capture client never connected to the test pipe")
        }

        time.Sleep(8 * time.Second)
        close(stop)
        select {
        case err := <-capDone:
                if err != nil {
                        t.Fatalf("runCapture: %v", err)
                }
        case <-time.After(15 * time.Second):
                t.Fatal("runCapture did not stop")
        }
        // Close the pipe file (cancels the reader's pending Read via the
        // runtime poller), then bound the reader exit. Never raw
        // CloseHandle: the handle belongs to pipeFile now.
        pipeFile.Close()
        select {
        case <-readerDone:
        case <-time.After(10 * time.Second):
                t.Fatal("pipe reader did not exit after close")
        }

        mu.Lock()
        defer mu.Unlock()
        if len(frames) == 0 {
                t.Skip("no packets observed on this host; capture path unproven here, not broken")
        }
        decoded := 0
        for _, fr := range frames {
                if len(fr) < 4 {
                        continue
                }
                size := int(binary.LittleEndian.Uint32(fr[0:4]))
                if size <= 0 || len(fr)-4 < size {
                        continue
                }
                if _, derr := DeserializeDispatch(fr[4 : 4+size]); derr == nil {
                        decoded++
                }
        }
        if decoded == 0 {
                t.Fatalf("%d frames arrived but none decode as CanonicalEvent", len(frames))
        }
        t.Logf("capture-to-pipe: %d frames, %d canonical", len(frames), decoded)
}
