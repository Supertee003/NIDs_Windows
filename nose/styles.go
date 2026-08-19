package main

// =====================================================================
// styles.go — AEGIS NOSE v5.0 Lipgloss Style Definitions
// =====================================================================
//  v5.0: Cool-tone palette (ฟ้า/เขียว/เทา) — Monitor/Analytics dashboard
//  "จมูกดมกลิ่นหาความผิดปกติ" — เน้น Sniffing, Traffic, Health
// =====================================================================

import "github.com/charmbracelet/lipgloss"

// ── Color Palette — Cool Tones (v5.0) ──
var (
        // Primary: Cool blues & cyans (Monitor/Analytics feel)
        colorCyan    = lipgloss.Color("#00D4FF")
        colorGreen   = lipgloss.Color("#00FF87")
        colorRed     = lipgloss.Color("#FF4757")
        colorYellow  = lipgloss.Color("#FFC048")
        colorBlue    = lipgloss.Color("#4C8BF5")    // Primary panel border
        colorOrange  = lipgloss.Color("#FF8C42")
        colorDim     = lipgloss.Color("#6C7A89")    // Slightly blue-gray
        colorWhite   = lipgloss.Color("#E8E8E8")
        colorMagenta = lipgloss.Color("#C792EA")
        colorBgDark  = lipgloss.Color("#0D1117")
        colorBgPanel = lipgloss.Color("#161B22")

        // v5.0: Additional cool-tone accents
        colorTeal    = lipgloss.Color("#1ABC9C")    // For health/good status
        colorSkyBlue = lipgloss.Color("#87CEEB")    // For secondary info
        colorSlate   = lipgloss.Color("#778899")    // For muted labels
)

// ── Title / Header ──
var (
        titleStyle = lipgloss.NewStyle().
                        Bold(true).
                        Foreground(colorCyan).
                        MarginBottom(1).
                        Padding(0, 1)

        subtitleStyle = lipgloss.NewStyle().
                        Foreground(colorDim).
                        Padding(0, 1)
)

// ── Panel (bordered box) — v5.0: All panels use cool-tone borders ──
var (
        // Main panels: blue border (cool monitor feel)
        panelStyle = lipgloss.NewStyle().
                        Border(lipgloss.RoundedBorder()).
                        BorderForeground(colorBlue).
                        BorderBackground(colorBgDark).
                        Padding(0, 1)

        // Traffic/Sniffing panel: teal border (network focus)
        panelTrafficStyle = lipgloss.NewStyle().
                                Border(lipgloss.RoundedBorder()).
                                BorderForeground(colorTeal).
                                BorderBackground(colorBgDark).
                                Padding(0, 1)

        // Raw stream panel: cyan border (data flow)
        panelStreamStyle = lipgloss.NewStyle().
                                Border(lipgloss.RoundedBorder()).
                                BorderForeground(colorCyan).
                                BorderBackground(colorBgDark).
                                Padding(0, 1)

        // Health panel: green border
        panelHealthStyle = lipgloss.NewStyle().
                                Border(lipgloss.RoundedBorder()).
                                BorderForeground(colorGreen).
                                BorderBackground(colorBgDark).
                                Padding(0, 1)
)

// ── Section Headers — v5.0: Cool tones ──
var (
        sectionStyle = lipgloss.NewStyle().
                        Bold(true).
                        Foreground(colorBlue)

        sectionTrafficStyle = lipgloss.NewStyle().
                                Bold(true).
                                Foreground(colorTeal)

        sectionStreamStyle = lipgloss.NewStyle().
                                Bold(true).
                                Foreground(colorCyan)

        sectionHealthStyle = lipgloss.NewStyle().
                                Bold(true).
                                Foreground(colorGreen)
)

// ── Labels & Values ──
var (
        labelStyle = lipgloss.NewStyle().
                        Foreground(colorSlate)   // v5.0: Slate instead of dim

        valueStyle = lipgloss.NewStyle().
                        Foreground(colorWhite)

        valueGreenStyle = lipgloss.NewStyle().
                        Foreground(colorGreen)

        valueRedStyle = lipgloss.NewStyle().
                        Foreground(colorRed)

        valueYellowStyle = lipgloss.NewStyle().
                        Foreground(colorYellow)

        valueCyanStyle = lipgloss.NewStyle().
                        Foreground(colorCyan)

        valueMagentaStyle = lipgloss.NewStyle().
                        Foreground(colorMagenta)

        valueTealStyle = lipgloss.NewStyle().
                        Foreground(colorTeal)

        valueBlueStyle = lipgloss.NewStyle().
                        Foreground(colorBlue)
)

// ── Status Indicators ──
var (
        statusOKStyle = lipgloss.NewStyle().
                        Foreground(colorGreen).
                        Bold(true)

        statusWarnStyle = lipgloss.NewStyle().
                        Foreground(colorYellow).
                        Bold(true)

        statusNAStyle = lipgloss.NewStyle().
                        Foreground(colorDim)

        statusFailStyle = lipgloss.NewStyle().
                        Foreground(colorRed).
                        Bold(true)
)

// ── Bar Chart — v5.0: Teal bars instead of red ──
var (
        barFullStyle = lipgloss.NewStyle().
                        Foreground(colorTeal)

        barEmptyStyle = lipgloss.NewStyle().
                        Foreground(colorDim)
)

// ── Sparkline — v5.0: Cool colors ──
var (
        sparkRXStyle = lipgloss.NewStyle().
                        Foreground(colorTeal)    // Teal for RX

        sparkTXStyle = lipgloss.NewStyle().
                        Foreground(colorSkyBlue)  // Sky blue for TX
)

// ── Footer ──
var (
        footerStyle = lipgloss.NewStyle().
                        Foreground(colorDim).
                        MarginTop(1).
                        PaddingLeft(1)

        separatorStyle = lipgloss.NewStyle().
                        Foreground(colorDim).
                        SetString("─")
)

// ── DEFCON Level Colors ──
var defconColors = map[int]lipgloss.Style{
        1: valueRedStyle,
        2: valueRedStyle,
        3: valueYellowStyle,
        4: valueGreenStyle,
        5: valueCyanStyle,
}

// ── Panel width (for layout calculations) ──
// v5.1: Wider panels + dynamic layout constants
const (
        panelWidth     = 44     // v5.1: wider (was 40)
        sparklineLen   = 24     // v5.0: longer sparkline (was 20)
        maxHistorySize = 24     // v5.0: more history points (was 20)
        barMaxWidth    = 12     // v5.0: wider bars (was 10)
        topTalkersCount = 5     // Number of top talkers to show
        rawStreamSize  = 8      // Number of raw stream entries to show
        streamWidth    = 90     // v5.1: explicit width for raw stream panel
        minTermWidth   = 80     // Minimum terminal width for side-by-side layout
)
