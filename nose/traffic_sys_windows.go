//go:build windows

// NOSE-SYS-143: real system traffic source (IP Helper, read-only).
//
// readTrafficFromSystem replaces the always-failing stub with live OS
// telemetry, so the TUI sparkline and status JSON carry real packet and
// byte rates. Design notes:
//
//   - Read-only OS calls only (GetAdaptersAddresses, GetIfEntry,
//     GetTcpTable2). No capture, no drivers, no admin required, no
//     enforcement surface of any kind.
//   - Cumulative 32-bit NIC counters are differenced here; wrap-around is
//     handled, which keeps the scheme accurate up to ~34 Gbps at 1-second
//     sampling. A machine reboot between samples can show one odd tick;
//     the next tick resynchronizes.
//   - ActiveConns counts ESTABLISHED TCP endpoints only (loopback
//     included), not LISTEN sockets.
//   - Single caller: trafficCollector (one goroutine). Package state below
//     is therefore race-free by construction; tests exercise only the
//     pure helpers, never this live path.
package main

import (
        "encoding/binary"
        "errors"
        "fmt"
        "sync"
        "time"
        "unsafe"

        "golang.org/x/sys/windows"
)

const (
        // Win32 error and TCP states used by the raw GetTcpTable2 path.
        tcpErrInsufficientBuffer = 122 // ERROR_INSUFFICIENT_BUFFER
        mibTCPStateEstab         = 5   // MIB_TCP_STATE_ESTABLISHED
        tcpRowSize               = 28  // 7 DWORDs per MIB_TCPROW2
)

// ifaceTotals are cumulative OS counters plus the current ESTAB count.
type ifaceTotals struct {
        rxPkts uint64
        txPkts uint64
        rxBytes uint64
        txBytes uint64
}

var (
        sysCallOnce sync.Once
        procGetTcpTable2 *windows.LazyProc
)

func tcpTableProc() *windows.LazyProc {
        sysCallOnce.Do(func() {
                mod := windows.NewLazySystemDLL("iphlpapi.dll")
                procGetTcpTable2 = mod.NewProc("GetTcpTable2")
        })
        return procGetTcpTable2
}

// ratePerSec converts a cumulative 32-bit NIC counter pair into a rate,
// tolerating one wrap between samples.
func ratePerSec(cur, prev uint64, dtSec float64) float64 {
        if dtSec <= 0 {
                return 0
        }
        var delta uint64
        if cur >= prev {
                delta = cur - prev
        } else {
                // 32-bit source counter wrapped exactly once.
                delta = (1<<32 - prev) + cur
        }
        return float64(delta) / dtSec
}

// readSystemTotals sums operational non-loopback adapters (octets +
// unicast/non-unicast packets) and counts established TCP endpoints.
func readSystemTotals() (ifaceTotals, int, error) {
        var totals ifaceTotals
        var size uint32
        err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, 0, 0, nil, &size)
        if err != windows.ERROR_BUFFER_OVERFLOW {
                return totals, 0, fmt.Errorf("adapter size probe: %v", err)
        }
        buf := make([]byte, size)
        aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
        if err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, 0, 0, aa, &size); err != nil {
                return totals, 0, fmt.Errorf("adapter enumerate: %v", err)
        }
        adapters := 0
        for cur := aa; cur != nil; cur = cur.Next {
                var row windows.MibIfRow
                row.Index = cur.IfIndex
                if err := windows.GetIfEntry(&row); err != nil {
                        continue
                }
                // Up (1) plus Dormant (5): dormant virtual/Wi-Fi adapters
                // still pass packets (observed live on Hyper-V/VMware
                // interfaces); anything else carries no live counters.
                if row.OperStatus != windows.IfOperStatusUp &&
                        row.OperStatus != windows.IfOperStatusDormant {
                        continue
                }
                if row.Type == windows.IF_TYPE_SOFTWARE_LOOPBACK {
                        continue
                }
                totals.rxPkts += uint64(row.InUcastPkts) + uint64(row.InNUcastPkts)
                totals.txPkts += uint64(row.OutUcastPkts) + uint64(row.OutNUcastPkts)
                totals.rxBytes += uint64(row.InOctets)
                totals.txBytes += uint64(row.OutOctets)
                adapters++
        }
        if adapters == 0 {
                return totals, 0, errors.New("no operational non-loopback adapter")
        }
        conns, err := countEstabTcp()
        if err != nil {
                return totals, 0, err
        }
        return totals, conns, nil
}

// countEstabTcp returns established TCP endpoints via GetTcpTable2.
func countEstabTcp() (int, error) {
        proc := tcpTableProc()
        var size uint32
        r1, _, _ := proc.Call(0, uintptr(unsafe.Pointer(&size)), 1)
        if r1 != uintptr(tcpErrInsufficientBuffer) {
                return 0, fmt.Errorf("tcp table sizing: rc=%d", r1)
        }
        buf := make([]byte, size)
        r1, _, _ = proc.Call(uintptr(unsafe.Pointer(&buf[0])),
                uintptr(unsafe.Pointer(&size)), 1)
        if r1 != 0 {
                return 0, fmt.Errorf("tcp table read: rc=%d", r1)
        }
        return parseTcpTable(buf)
}

// parseTcpTable counts ESTABLISHED rows in a MIB_TCPTABLE2 buffer
// (NumEntries u32, then 28-byte MIB_TCPROW2 rows; state is row DWORD 0).
func parseTcpTable(buf []byte) (int, error) {
        if len(buf) < 4 {
                return 0, errors.New("tcp table too short for header")
        }
        n := binary.LittleEndian.Uint32(buf[0:4])
        if uint64(len(buf)) < 4+uint64(n)*tcpRowSize {
                return 0, fmt.Errorf("tcp table truncated: %d rows need %d bytes, have %d",
                        n, 4+int(n)*tcpRowSize, len(buf))
        }
        estab := 0
        for i := uint32(0); i < n; i++ {
                off := 4 + int(i)*tcpRowSize
                if binary.LittleEndian.Uint32(buf[off:off+4]) == mibTCPStateEstab {
                        estab++
                }
        }
        return estab, nil
}

var (
        sysPrev     ifaceTotals
        sysPrevTime int64
        sysHavePrev bool
)

// readTrafficFromSystem samples live OS counters and returns per-second
// rates plus the current ESTAB count. First call has no baseline, so rates
// come out zero and converge on the next tick. Numbers are real; the
// caller keeps Simulated marked while TopTalkers stay synthetic.
func readTrafficFromSystem() (TrafficData, error) {
        totals, conns, err := readSystemTotals()
        if err != nil {
                return TrafficData{}, err
        }
        now := time.Now().UnixNano()
        var data TrafficData
        if sysHavePrev {
                dt := float64(now-sysPrevTime) / 1e9
                data.RxPktsPerSec = int64(ratePerSec(totals.rxPkts, sysPrev.rxPkts, dt))
                data.TxPktsPerSec = int64(ratePerSec(totals.txPkts, sysPrev.txPkts, dt))
                data.RxBytesPerSec = ratePerSec(totals.rxBytes, sysPrev.rxBytes, dt)
                data.TxBytesPerSec = ratePerSec(totals.txBytes, sysPrev.txBytes, dt)
        }
        data.ActiveConns = int64(conns)
        sysPrev, sysPrevTime, sysHavePrev = totals, now, true
        return data, nil
}
