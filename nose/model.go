package main

// =====================================================================
// model.go — AEGIS NOSE v5.0 Bubbletea Model + Rendering
// =====================================================================
//  "จมูกดมกลิ่นหาความผิดปกติ" — Sniffing, Traffic & Health
//
//  v5.0 Layout:
//    - Header (title + version)
//    - Row 1: System Health + Network Traffic (side by side)
//    - Row 2: Top Talkers + Protocol Distribution (side by side)
//    - Row 3: Raw Packet/Event Stream (full width)
//    - Row 4: Sensor Health (full width)
//    - Footer
//
//  Changes from v4.0:
//    - Threat Intel → Raw Packet Stream (scrolling event log)
//    - Top Attack Types → Top Talkers (IP bandwidth) + Protocol Dist
//    - Enhanced System Resources with more detail
//    - Cool-tone color scheme
// =====================================================================

import (
        "encoding/json"
        "fmt"
        "os"
        "runtime"
        "strings"
        "time"

        tea "github.com/charmbracelet/bubbletea"
        "github.com/charmbracelet/bubbles/spinner"
        "github.com/charmbracelet/lipgloss"
)

// ── Custom Messages ──

type resourceMsg ResourceData
type trafficMsg TrafficData
type threatMsg ThreatData
type tickMsg time.Time

// ── Model ──

type model struct {
        width  int
        height int
        ready  bool

        spinner spinner.Model

        resource ResourceData
        traffic  TrafficData
        threats  ThreatData

        // Traffic history for sparkline visualization
        rxHistory []int64
        txHistory []int64

        // Channels (read-only in model)
        resourceCh chan ResourceData
        trafficCh  chan TrafficData
        threatCh   chan ThreatData

        // State
        startTime time.Time
        jsonCount int64
        defcon    int
}

// ── Constructor ──

func initialModel(resourceCh chan ResourceData, trafficCh chan TrafficData, threatCh chan ThreatData, startTime time.Time) model {
        sp := spinner.New()
        sp.Spinner = spinner.Dot
        sp.Style = lipgloss.NewStyle().Foreground(colorCyan)

        return model{
                spinner:    sp,
                resourceCh: resourceCh,
                trafficCh:  trafficCh,
                threatCh:   threatCh,
                startTime:  startTime,
                rxHistory:  make([]int64, 0, maxHistorySize),
                txHistory:  make([]int64, 0, maxHistorySize),
                defcon:     5,
                resource: ResourceData{
                        GoVersion: runtime.Version(),
                        OS:        runtime.GOOS,
                        Arch:      runtime.GOARCH,
                        CPUCores:  runtime.NumCPU(),
                },
        }
}

// ── Init ──

func (m model) Init() tea.Cmd {
        return tea.Batch(
                m.spinner.Tick,
                waitForResource(m.resourceCh),
                waitForTraffic(m.trafficCh),
                waitForThreat(m.threatCh),
                tickCmd(),
        )
}

// ── Channel Wait Commands ──

func waitForResource(ch chan ResourceData) tea.Cmd {
        return func() tea.Msg {
                return resourceMsg(<-ch)
        }
}

func waitForTraffic(ch chan TrafficData) tea.Cmd {
        return func() tea.Msg {
                return trafficMsg(<-ch)
        }
}

func waitForThreat(ch chan ThreatData) tea.Cmd {
        return func() tea.Msg {
                return threatMsg(<-ch)
        }
}

func tickCmd() tea.Cmd {
        return tea.Tick(2*time.Second, func(t time.Time) tea.Msg {
                return tickMsg(t)
        })
}

// ── Update ──

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
        switch msg := msg.(type) {

        case tea.WindowSizeMsg:
                m.width = msg.Width
                m.height = msg.Height
                m.ready = true
                return m, nil

        case tea.KeyMsg:
                switch msg.String() {
                case "q", "ctrl+c":
                        return m, tea.Quit
                }

        case resourceMsg:
                m.resource = ResourceData(msg)
                return m, waitForResource(m.resourceCh)

        case trafficMsg:
                m.traffic = TrafficData(msg)
                // Update sparkline history (ring buffer)
                m.rxHistory = append(m.rxHistory, m.traffic.RxPktsPerSec)
                if len(m.rxHistory) > maxHistorySize {
                        m.rxHistory = m.rxHistory[1:]
                }
                m.txHistory = append(m.txHistory, m.traffic.TxPktsPerSec)
                if len(m.txHistory) > maxHistorySize {
                        m.txHistory = m.txHistory[1:]
                }
                return m, waitForTraffic(m.trafficCh)

        case threatMsg:
                m.threats = ThreatData(msg)
                m.defcon = getDEFCON(m.threats)
                return m, waitForThreat(m.threatCh)

        case tickMsg:
                m.jsonCount++
                m.resource.UptimeSecs = int64(time.Since(m.startTime).Seconds())
                // Output JSON to stderr (for Bridge/Brain to consume)
                output := NoseOutput{
                        Timestamp: time.Now().Format("2006-01-02T15:04:05"),
                        Resource:  m.resource,
                        Traffic:   m.traffic,
                        Threats:   m.threats,
                }
                if jsonBytes, err := json.Marshal(output); err == nil {
                        fmt.Fprintf(os.Stderr, "%s\n", string(jsonBytes))
                }
                return m, tickCmd()
        }

        var cmd tea.Cmd
        m.spinner, cmd = m.spinner.Update(msg)
        return m, cmd
}

// ── View ──
// v5.0: "จมูกดมกลิ่นหาความผิดปกติ" Layout

func (m model) View() string {
        if !m.ready {
                return fmt.Sprintf("\n  %s Initializing AEGIS NOSE v5.1...\n\n", m.spinner.View())
        }

        // ── Calculate dynamic panel widths ──
        // Each row has 2 panels side by side. Subtract borders/padding (6 per panel)
        halfWidth := (m.width / 2) - 4
        if halfWidth < panelWidth {
                halfWidth = panelWidth
        }
        if halfWidth > 60 {
                halfWidth = 60 // cap to avoid too-wide panels
        }
        fullWidth := m.width - 4 // full-width panels (stream, sensor)
        if fullWidth < streamWidth {
                fullWidth = streamWidth
        }

        // ── Header ──
        header := m.renderHeader()

        // ── Row 1: System Health + Network Traffic (side by side) ──
        healthPanel := m.renderHealthDynamic(halfWidth)
        trafficPanel := m.renderTrafficDynamic(halfWidth)
        row1 := lipgloss.JoinHorizontal(lipgloss.Top, healthPanel, trafficPanel)

        // ── Row 2: Top Talkers + Protocol Distribution (side by side) ──
        talkersPanel := m.renderTopTalkersDynamic(halfWidth)
        protoPanel := m.renderProtocolDistDynamic(halfWidth)
        row2 := lipgloss.JoinHorizontal(lipgloss.Top, talkersPanel, protoPanel)

        // ── Row 3: Raw Packet/Event Stream (full width) ──
        streamPanel := m.renderRawStreamDynamic(fullWidth)

        // ── Row 4: Sensor Health ──
        sensorBar := m.renderSensorBar()

        // ── Footer ──
        footer := m.renderFooter()

        return lipgloss.JoinVertical(lipgloss.Left,
                header,
                row1,
                row2,
                streamPanel,
                sensorBar,
                footer,
        )
}

// =====================================================================
// Panel Rendering Functions
// =====================================================================

// ── renderHeader ──
func (m model) renderHeader() string {
        uptimeStr := formatUptime(m.resource.UptimeSecs)
        line1 := titleStyle.Render("⬡ AEGIS NOSE [Go] v5.0 — Sniffing, Traffic & Health")
        line2 := subtitleStyle.Render(fmt.Sprintf("  \"จมูกดมกลิ่นหาความผิดปกติ\" │ Uptime: %s │ Go: %s │ %s/%s │ %d cores",
                uptimeStr, m.resource.GoVersion, m.resource.OS, m.resource.Arch, m.resource.CPUCores))
        return lipgloss.JoinVertical(lipgloss.Left, line1, line2)
}

// ── renderHealth — v5.1: Dynamic width ──
func (m model) renderHealthDynamic(w int) string {
        var b strings.Builder

        b.WriteString(sectionHealthStyle.Render("System Health"))
        b.WriteString("\n")

        b.WriteString(fmt.Sprintf("  %-16s %s\n",
                labelStyle.Render("Mem Alloc:"),
                valueGreenStyle.Render(fmt.Sprintf("%d MB", m.resource.AllocMB))))
        b.WriteString(fmt.Sprintf("  %-16s %s\n",
                labelStyle.Render("Mem Sys:"),
                valueStyle.Render(fmt.Sprintf("%d MB", m.resource.SysMB))))
        b.WriteString(fmt.Sprintf("  %-16s %s\n",
                labelStyle.Render("Heap InUse:"),
                valueTealStyle.Render(fmt.Sprintf("%d MB", m.resource.HeapInUseMB))))
        b.WriteString(fmt.Sprintf("  %-16s %s\n",
                labelStyle.Render("Stack InUse:"),
                valueStyle.Render(fmt.Sprintf("%d MB", m.resource.StackInUseMB))))

        b.WriteString(fmt.Sprintf("  %-16s %s\n",
                labelStyle.Render("Goroutines:"),
                valueGreenStyle.Render(fmt.Sprintf("%d", m.resource.Goroutines))))
        b.WriteString(fmt.Sprintf("  %-16s %s\n",
                labelStyle.Render("GC Cycles:"),
                valueYellowStyle.Render(fmt.Sprintf("%d", m.resource.NumGC))))
        b.WriteString(fmt.Sprintf("  %-16s %s\n",
                labelStyle.Render("GC Pause:"),
                valueCyanStyle.Render(fmt.Sprintf("%d ms", m.resource.GCPauseMs))))
        b.WriteString(fmt.Sprintf("  %-16s %s",
                labelStyle.Render("Uptime:"),
                valueCyanStyle.Render(formatUptime(m.resource.UptimeSecs))))

        return panelHealthStyle.Width(w).Render(b.String())
}

// ── renderTraffic — v5.1: Dynamic width ──
func (m model) renderTrafficDynamic(w int) string {
        var b strings.Builder

        b.WriteString(sectionTrafficStyle.Render("Network Traffic"))
        b.WriteString("\n")

        b.WriteString(fmt.Sprintf("  %-16s %s\n",
                labelStyle.Render("RX Pkts/sec:"),
                valueGreenStyle.Render(formatComma(m.traffic.RxPktsPerSec))))
        b.WriteString(fmt.Sprintf("  %-16s %s\n",
                labelStyle.Render("TX Pkts/sec:"),
                valueGreenStyle.Render(formatComma(m.traffic.TxPktsPerSec))))
        b.WriteString(fmt.Sprintf("  %-16s %s\n",
                labelStyle.Render("Active Conns:"),
                valueYellowStyle.Render(formatComma(m.traffic.ActiveConns))))
        b.WriteString(fmt.Sprintf("  %-16s %s\n",
                labelStyle.Render("RX Bandwidth:"),
                valueTealStyle.Render(formatBytes(m.traffic.RxBytesPerSec))))
        b.WriteString(fmt.Sprintf("  %-16s %s\n",
                labelStyle.Render("TX Bandwidth:"),
                valueBlueStyle.Render(formatBytes(m.traffic.TxBytesPerSec))))

        // v5.0: Enhanced sparkline visualization (longer, with labels)
        b.WriteString("\n")
        if len(m.rxHistory) > 1 {
                rxSpark := sparkRXStyle.Render(sparkline(m.rxHistory))
                b.WriteString(fmt.Sprintf("  RX %s\n", rxSpark))
        }
        if len(m.txHistory) > 1 {
                txSpark := sparkTXStyle.Render(sparkline(m.txHistory))
                b.WriteString(fmt.Sprintf("  TX %s", txSpark))
        }

        return panelTrafficStyle.Width(w).Render(b.String())
}

// ── renderTopTalkers — v5.1: Dynamic width ──
// แสดง IP ที่กิน Bandwidth สูงสุด
func (m model) renderTopTalkersDynamic(w int) string {
        var b strings.Builder

        b.WriteString(sectionTrafficStyle.Render("Top Talkers"))
        b.WriteString("\n")

        talkers := sortTopTalkers(m.traffic.TopTalkers)
        if len(talkers) == 0 {
                b.WriteString(fmt.Sprintf("  %s", statusNAStyle.Render("No traffic data yet")))
                return panelTrafficStyle.Width(w).Render(b.String())
        }

        // Find max for bar scaling
        var maxTotal int64 = 1
        for i, t := range talkers {
                if i >= topTalkersCount {
                        break
                }
                if t.Total > maxTotal {
                        maxTotal = t.Total
                }
        }

        // Display top N with bar + bandwidth
        for i, t := range talkers {
                if i >= topTalkersCount {
                        break
                }
                bar := barFullStyle.Render(renderBar(int(t.Total), int(maxTotal), barMaxWidth))
                bwStr := valueTealStyle.Render(formatBytesTotal(t.Total))
                b.WriteString(fmt.Sprintf("  %-15s %s %s\n",
                        labelStyle.Render(t.IP),
                        bar,
                        bwStr))
        }

        return panelTrafficStyle.Width(w).Render(b.String())
}

// ── renderProtocolDist — v5.1: Dynamic width ──
// แสดง Protocol Distribution (TCP/UDP/ICMP/Other)
func (m model) renderProtocolDistDynamic(w int) string {
        var b strings.Builder

        b.WriteString(sectionTrafficStyle.Render("Protocol Distribution"))
        b.WriteString("\n")

        if len(m.traffic.Protocols) == 0 {
                b.WriteString(fmt.Sprintf("  %s", statusNAStyle.Render("No protocol data yet")))
                return panelTrafficStyle.Width(w).Render(b.String())
        }

        // Find max for bar scaling
        var maxCount int64 = 1
        for _, p := range m.traffic.Protocols {
                if p.Count > maxCount {
                        maxCount = p.Count
                }
        }

        // Display each protocol with bar
        for _, p := range m.traffic.Protocols {
                bar := barFullStyle.Render(renderBar(int(p.Count), int(maxCount), barMaxWidth))
                countStr := valueTealStyle.Render(formatComma(p.Count))

                // Color protocol name
                var protoStyle lipgloss.Style
                switch p.Name {
                case "TCP":
                        protoStyle = valueTealStyle
                case "UDP":
                        protoStyle = valueBlueStyle
                case "ICMP":
                        protoStyle = valueYellowStyle
                default:
                        protoStyle = valueStyle
                }

                b.WriteString(fmt.Sprintf("  %-10s %s %s\n",
                        protoStyle.Render(p.Name),
                        bar,
                        countStr))
        }

        return panelTrafficStyle.Width(w).Render(b.String())
}

// ── renderRawStream — v5.1: Dynamic width with truncation ──
// "Raw Event/Packet Sniffing Stream" — แสดง Log การเชื่อมต่อ/แพ็กเก็ตแบบเรียลไทม์
func (m model) renderRawStreamDynamic(w int) string {
        var b strings.Builder

        b.WriteString(sectionStreamStyle.Render("Raw Packet Sniffing Stream"))
        b.WriteString("\n")

        if len(m.threats.RawStream) == 0 {
                b.WriteString(fmt.Sprintf("  %s  %s\n",
                statusNAStyle.Render("○"),
                statusNAStyle.Render("No packets intercepted — waiting for anomalous events...")))
                return panelStreamStyle.Width(w).Render(b.String())
        }

        // Display raw stream entries (newest first, limited to rawStreamSize)
        count := 0
        for i := len(m.threats.RawStream) - 1; i >= 0 && count < rawStreamSize; i-- {
                entry := m.threats.RawStream[i]

                // Color based on event type / policy
                var detailStyle lipgloss.Style
                var indicator string
                switch entry.Detail {
                case "Drop", "Block", "BLOCK":
                        detailStyle = valueRedStyle
                        indicator = "✕"
                case "Alert", "AlertOnly":
                        detailStyle = valueYellowStyle
                        indicator = "⚡"
                default:
                        detailStyle = valueTealStyle
                        indicator = "·"
                }

                // Truncate source for display
                srcDisplay := entry.Source
                if len(srcDisplay) > 16 {
                        srcDisplay = srcDisplay[:13] + "..."
                }
                // Truncate event type
                evtDisplay := entry.EventType
                if len(evtDisplay) > 18 {
                        evtDisplay = evtDisplay[:15] + "..."
                }
                // Truncate detail
                detDisplay := entry.Detail
                if len(detDisplay) > 10 {
                        detDisplay = detDisplay[:7] + "..."
                }

                b.WriteString(fmt.Sprintf("  %s %-8s %-16s %-18s %s\n",
                        detailStyle.Render(indicator),
                        valueCyanStyle.Render(entry.Timestamp),
                        labelStyle.Render(srcDisplay),
                        valueWhiteStyle(evtDisplay),
                        detailStyle.Render(detDisplay)))
                count++
        }

        // Show total events count
        if m.threats.TotalEvents > 0 {
                b.WriteString(fmt.Sprintf("\n  %s Total events: %s │ Unique threats: %s",
                        statusNAStyle.Render("─"),
                        valueCyanStyle.Render(formatComma(int64(m.threats.TotalEvents))),
                        valueYellowStyle.Render(fmt.Sprintf("%d", m.threats.UniqueThreats))))
        }

        return panelStreamStyle.Width(w).Render(b.String())
}

// valueWhiteStyle helper
func valueWhiteStyle(s string) string {
        return lipgloss.NewStyle().Foreground(colorWhite).Render(s)
}

// ── renderSensorBar ──
func (m model) renderSensorBar() string {
        var b strings.Builder

        b.WriteString(sectionHealthStyle.Render("Sensor Health"))
        b.WriteString("\n")

        b.WriteString(fmt.Sprintf("  %s ResourceSensor  %s (2s)    ",
                statusOKStyle.Render("●"),
                statusOKStyle.Render("OK")))
        b.WriteString(fmt.Sprintf("%s TrafficSensor   %s (1s)\n",
                statusOKStyle.Render("●"),
                statusOKStyle.Render("OK")))
        b.WriteString(fmt.Sprintf("  %s ThreatScanner   %s (5s)    ",
                statusOKStyle.Render("●"),
                statusOKStyle.Render("OK")))
        b.WriteString(fmt.Sprintf("%s PacketCapture    %s\n",
                statusNAStyle.Render("○"),
                statusNAStyle.Render("N/A")))

        b.WriteString(fmt.Sprintf("\n  JSON: %s outputs  │  Refresh: 2s  │  Press %s to quit",
                valueCyanStyle.Render(formatComma(m.jsonCount)),
                valueYellowStyle.Bold(true).Render("q")))

        return panelHealthStyle.Render(b.String())
}

// ── renderFooter ──
func (m model) renderFooter() string {
        return footerStyle.Render(
                fmt.Sprintf("  AEGIS NIDS — 5-Language NIDS │ NOSE v5.0 │ Sniffing, Traffic & Health │ %s",
                        time.Now().Format("15:04:05")))
}
