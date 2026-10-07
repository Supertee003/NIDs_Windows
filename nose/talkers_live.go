// NOSE-TALK-145: live Top Talkers from Npcap capture (opt-in).
//
// The traffic panel's numbers went real in NOSE-SYS-143, but TopTalkers
// stayed hardcoded. This file attributes captured bytes per endpoint so
// the talkers (and protocol shares) can go real too — without touching
// the canonical capture-to-pipe path (runCapture is unchanged).
//
// Design rules:
//   - Opt-in only (--live-talkers). Default behavior is byte-identical:
//     synthetic talkers, Simulated marked.
//   - Passive, non-promiscuous capture, BPF "ip or ip6", no pipe writes,
//     no injection. Any open/BPF failure returns an error and the caller
//     keeps synthetic data (fail-silent with one stderr note).
//   - Attribution is endpoint-symmetric and needs no local-IP knowledge:
//     bytes FROM an IP count as its Tx, bytes TO it as its Rx. Our own
//     address therefore ranks honestly instead of being hidden.
//   - Freshness-gated: a snapshot counts as live only with entries newer
//     than liveFreshnessNs. A stopped feed degrades back to synthetic
//     automatically, no flags to manage.
//   - Bounded memory: the table prunes to liveTableKeep entries past
//     liveTableCap, so a multi-day run cannot grow it without bound.
package main

import (
        "fmt"
        "os"
        "sort"
        "sync"
        "time"

        "github.com/google/gopacket"
        "github.com/google/gopacket/layers"
        "github.com/google/gopacket/pcap"
)

const (
        // talkersFreshnessNs bounds how stale a snapshot may be to count
        // as live (about ten collector ticks).
        talkersFreshnessNs = int64(15 * time.Second)
        // talkersTopN matches the panel's row count.
        talkersTopN = 5
        // talkersTableCap/Keep bound memory; prune keeps the heaviest.
        talkersTableCap  = 1024
        talkersTableKeep = 512
)

type talkerStat struct {
        rx int64
        tx int64
}

var liveTalkerTable = struct {
        sync.Mutex
        byIP    map[string]*talkerStat
        proto   [4]int64 // TCP, UDP, ICMP, other (cumulative observed packets)
        updated int64    // UnixNano of last observe
}{byIP: map[string]*talkerStat{}}

// observeLivePacket attributes one captured packet. Pure accounting under
// a mutex; safe for the capture goroutine and unit tests.
func observeLivePacket(src, dst string, length int, ipProto uint8) {
        if length <= 0 {
                return
        }
        liveTalkerTable.Lock()
        defer liveTalkerTable.Unlock()
        s := liveTalkerTable.byIP[src]
        if s == nil {
                s = &talkerStat{}
                liveTalkerTable.byIP[src] = s
        }
        s.tx += int64(length)
        d := liveTalkerTable.byIP[dst]
        if d == nil {
                d = &talkerStat{}
                liveTalkerTable.byIP[dst] = d
        }
        d.rx += int64(length)
        switch ipProto {
        case 6:
                liveTalkerTable.proto[0]++
        case 17:
                liveTalkerTable.proto[1]++
        case 1:
                liveTalkerTable.proto[2]++
        default:
                liveTalkerTable.proto[3]++
        }
        liveTalkerTable.updated = time.Now().UnixNano()
        if len(liveTalkerTable.byIP) > talkersTableCap {
                pruneLiveTalkersLocked()
        }
}

// pruneLiveTalkersLocked keeps the heaviest talkersTableKeep endpoints.
// Caller must hold liveTalkerTable.Mutex.
func pruneLiveTalkersLocked() {
        type kv struct {
                ip string
                total int64
        }
        all := make([]kv, 0, len(liveTalkerTable.byIP))
        for ip, s := range liveTalkerTable.byIP {
                all = append(all, kv{ip, s.rx + s.tx})
        }
        sort.Slice(all, func(i, j int) bool { return all[i].total > all[j].total })
        keep := map[string]*talkerStat{}
        for i := 0; i < len(all) && i < talkersTableKeep; i++ {
                keep[all[i].ip] = liveTalkerTable.byIP[all[i].ip]
        }
        liveTalkerTable.byIP = keep
}

// snapshotLiveTalkersAt returns the top entries plus cumulative protocol
// packet counts. ok is false when nothing was ever observed or the table
// went stale, in which case callers must keep synthetic data.
func snapshotLiveTalkersAt(now int64, topN int) ([]TopTalkerEntry, [4]int64, bool) {
        liveTalkerTable.Lock()
        defer liveTalkerTable.Unlock()
        if len(liveTalkerTable.byIP) == 0 {
                return nil, [4]int64{}, false
        }
        if now-liveTalkerTable.updated > talkersFreshnessNs {
                return nil, [4]int64{}, false
        }
        type kv struct {
                ip string
                s  *talkerStat
        }
        all := make([]kv, 0, len(liveTalkerTable.byIP))
        for ip, s := range liveTalkerTable.byIP {
                all = append(all, kv{ip, s})
        }
        sort.Slice(all, func(i, j int) bool {
                ti := all[i].s.rx + all[i].s.tx
                tj := all[j].s.rx + all[j].s.tx
                if ti != tj {
                        return ti > tj
                }
                return all[i].ip < all[j].ip
        })
        if topN > len(all) {
                topN = len(all)
        }
        out := make([]TopTalkerEntry, 0, topN)
        for _, e := range all[:topN] {
                out = append(out, TopTalkerEntry{
                        IP:      e.ip,
                        RxBytes: e.s.rx,
                        TxBytes: e.s.tx,
                        Total:   e.s.rx + e.s.tx,
                })
        }
        return out, liveTalkerTable.proto, true
}

// applyLiveTalkers replaces synthetic talkers/protocols when the live
// table is fresh. numbersOK reports whether the numbers came from the
// system source; Simulated stays set unless every section is real.
func applyLiveTalkers(data *TrafficData, numbersOK bool) {
        talkers, proto, ok := snapshotLiveTalkersAt(time.Now().UnixNano(), talkersTopN)
        if !ok {
                data.Simulated = true
                return
        }
        data.TopTalkers = talkers
        data.Protocols = []ProtocolEntry{
                {Name: "TCP", Count: proto[0]},
                {Name: "UDP", Count: proto[1]},
                {Name: "ICMP", Count: proto[2]},
                {Name: "Other", Count: proto[3]},
        }
        data.Simulated = !numbersOK
}

// startLiveTalkersFeed opens a passive capture handle and feeds observed
// packets into the live table. It never writes to any pipe and never
// touches enforcement, policy, or detection state.
func startLiveTalkersFeed() error {
        iface, err := firstUpDevice()
        if err != nil {
                return fmt.Errorf("live talkers: %w", err)
        }
        handle, err := pcap.OpenLive(iface, 65535, false, 500*time.Millisecond)
        if err != nil {
                return fmt.Errorf("live talkers: open %s: %w", iface, err)
        }
        if err := handle.SetBPFFilter("ip or ip6"); err != nil {
                handle.Close()
                return fmt.Errorf("live talkers: bpf: %w", err)
        }
        fmt.Fprintf(os.Stderr, "[NOSE TALKERS] live feed on %s (non-promiscuous, no pipe)\n", iface)
        go func() {
                defer handle.Close()
                for {
                        data, _, err := handle.ReadPacketData()
                        if err != nil {
                                continue
                        }
                        packet := gopacket.NewPacket(data, handle.LinkType(), gopacket.NoCopy)
                        nl := packet.NetworkLayer()
                        if nl == nil {
                                continue
                        }
                        flow := nl.NetworkFlow()
                        src, dst := flow.Endpoints()
                        var proto uint8 = 255
                        switch l := nl.(type) {
                        case *layers.IPv4:
                                proto = uint8(l.Protocol)
                        case *layers.IPv6:
                                proto = uint8(l.NextHeader)
                        }
                        observeLivePacket(src.String(), dst.String(), len(data), proto)
                }
        }()
        return nil
}
