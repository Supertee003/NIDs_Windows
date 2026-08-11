package com.aegis.ui;

import com.vaadin.flow.component.html.H1;
import com.vaadin.flow.component.html.H2;
import com.vaadin.flow.component.html.Span;
import com.vaadin.flow.component.orderedlayout.HorizontalLayout;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.component.card.Card;
import com.vaadin.flow.component.chart.Chart;
import com.vaadin.flow.component.chart.model.ChartType;
import com.vaadin.flow.component.chart.model.DataSeries;
import com.vaadin.flow.component.chart.model.DataSeriesItem;
import com.vaadin.flow.component.grid.Grid;
import com.vaadin.flow.component.progressbar.ProgressBar;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.component.page.Push;

import java.time.Instant;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * DashboardView — Real-time AEGIS NIDS monitoring dashboard.
 *
 * Displays:
 *   - Live traffic throughput chart (packets/sec over time)
 *   - Alert rate gauge
 *   - Top talkers grid (IP → packet count)
 *   - System resource bars (CPU, Memory, Ring buffer usage)
 *   - Recent alerts table
 *
 * Auto-refreshes every 2 seconds via @Push (WebSocket).
 *
 * Layer 6: Java + Vaadin 24
 * Language: Java 17+
 */
@Route(value = "dashboard", layout = AegisMainLayout.class)
@Push
public class DashboardView extends VerticalLayout {

    // ─── Metric Cards ───
    private final Span packetsPerSecValue  = new Span("0");
    private final Span alertsPerSecValue   = new Span("0");
    private final Span droppedPerSecValue  = new Span("0");
    private final Span activeStreamsValue  = new Span("0");

    // ─── Progress Bars ───
    private final ProgressBar cpuBar       = new ProgressBar(0, 100, 0);
    private final ProgressBar memBar       = new ProgressBar(0, 100, 0);
    private final ProgressBar ringBar      = new ProgressBar(0, 100, 0);

    // ─── Throughput Chart ───
    private final Chart throughputChart;

    // ─── Recent Alerts Grid ───
    private final Grid<AlertRecord> alertsGrid;

    // ─── Refresh Scheduler ───
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    public DashboardView() {
        setSizeFull();
        setPadding(true);
        setSpacing(true);

        // ── Title ──
        add(new H1("AEGIS NIDS Dashboard"));

        // ── KPI Cards Row ──
        HorizontalLayout kpiRow = new HorizontalLayout();
        kpiRow.setWidthFull();
        kpiRow.add(
            createKpiCard("Packets/sec",   packetsPerSecValue),
            createKpiCard("Alerts/sec",    alertsPerSecValue),
            createKpiCard("Dropped/sec",   droppedPerSecValue),
            createKpiCard("Active Streams", activeStreamsValue)
        );
        add(kpiRow);

        // ── Resource Bars ──
        VerticalLayout resourceSection = new VerticalLayout();
        resourceSection.add(new H2("System Resources"));
        resourceSection.add(createLabeledBar("CPU Usage", cpuBar));
        resourceSection.add(createLabeledBar("Memory Usage", memBar));
        resourceSection.add(createLabeledBar("Ring Buffer", ringBar));
        add(resourceSection);

        // ── Throughput Chart ──
        throughputChart = new Chart(ChartType.AREASPLINE);
        throughputChart.setWidthFull();
        throughputChart.setHeight("300px");
        DataSeries series = new DataSeries();
        series.setName("Packets/sec");
        throughputChart.getConfiguration().addSeries(series);
        throughputChart.getConfiguration().setTitle("Network Traffic Throughput");
        add(throughputChart);

        // ── Alerts Grid ──
        alertsGrid = new Grid<>(AlertRecord.class);
        alertsGrid.setColumns("timestamp", "srcIp", "dstIp", "srcPort", "dstPort",
                              "protocol", "ruleName", "severity");
        alertsGrid.setWidthFull();
        alertsGrid.setHeight("250px");
        add(new H2("Recent Alerts"), alertsGrid);

        // ── Start auto-refresh ──
        startAutoRefresh();
    }

    private Card createKpiCard(String title, Span valueSpan) {
        Card card = new Card();
        VerticalLayout content = new VerticalLayout();
        content.add(new Span(title));
        valueSpan.getStyle().set("font-size", "2em").set("font-weight", "bold");
        content.add(valueSpan);
        card.add(content);
        return card;
    }

    private HorizontalLayout createLabeledBar(String label, ProgressBar bar) {
        HorizontalLayout layout = new HorizontalLayout();
        layout.add(new Span(label));
        bar.setWidth("300px");
        layout.add(bar);
        return layout;
    }

    /**
     * Auto-refresh dashboard metrics every 2 seconds.
     * Reads from Go performance monitor via named pipe or gRPC.
     */
    private void startAutoRefresh() {
        scheduler.scheduleAtFixedRate(() -> {
            getUI().ifPresent(ui -> ui.access(() -> {
                // In production: read from Go perf monitor via gRPC
                // For now: placeholder values
                PerfSnapshot snapshot = readPerfSnapshot();

                packetsPerSecValue.setText(String.format("%.0f", snapshot.packetsPerSec));
                alertsPerSecValue.setText(String.format("%.1f", snapshot.alertsPerSec));
                droppedPerSecValue.setText(String.format("%.1f", snapshot.droppedPerSec));
                activeStreamsValue.setText(String.valueOf(snapshot.activeStreams));

                cpuBar.setValue(snapshot.cpuPercent);
                memBar.setValue(snapshot.memPercent);
                ringBar.setValue(snapshot.ringPercent);

                // Append data point to throughput chart
                DataSeries series = (DataSeries) throughputChart.getConfiguration().getSeries()[0];
                series.addData(new DataSeriesItem(
                    Instant.now().toString(), snapshot.packetsPerSec));
                // Keep last 60 data points
                if (series.getData().size() > 60) {
                    series.setData(series.getData().subList(
                        series.getData().size() - 60, series.getData().size()));
                }
            }));
        }, 0, 2, TimeUnit.SECONDS);
    }

    /**
     * Read performance snapshot from Go monitor.
     * In production: gRPC call to perf_go service.
     */
    private PerfSnapshot readPerfSnapshot() {
        // Placeholder — production reads from gRPC/named pipe
        return new PerfSnapshot(
            Math.random() * 50000,  // packetsPerSec
            Math.random() * 10,     // alertsPerSec
            Math.random() * 0.5,    // droppedPerSec
            (int)(Math.random() * 500), // activeStreams
            Math.random() * 80,     // cpuPercent
            Math.random() * 60,     // memPercent
            Math.random() * 30      // ringPercent
        );
    }

    @Override
    protected void onDetach(com.vaadin.flow.component.DetachEvent event) {
        scheduler.shutdownNow();
        super.onDetach(event);
    }

    // ─── Data Classes ───

    static class PerfSnapshot {
        double packetsPerSec, alertsPerSec, droppedPerSec;
        int activeStreams;
        double cpuPercent, memPercent, ringPercent;

        PerfSnapshot(double pps, double aps, double dps, int streams,
                     double cpu, double mem, double ring) {
            this.packetsPerSec = pps;
            this.alertsPerSec = aps;
            this.droppedPerSec = dps;
            this.activeStreams = streams;
            this.cpuPercent = cpu;
            this.memPercent = mem;
            this.ringPercent = ring;
        }
    }

    public static class AlertRecord {
        public String timestamp;
        public String srcIp;
        public String dstIp;
        public int srcPort;
        public int dstPort;
        public String protocol;
        public String ruleName;
        public String severity;
    }
}
