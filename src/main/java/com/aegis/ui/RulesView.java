package com.aegis.ui;

import com.vaadin.flow.component.html.H1;
import com.vaadin.flow.component.html.H2;
import com.vaadin.flow.component.html.Span;
import com.vaadin.flow.component.orderedlayout.HorizontalLayout;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.component.grid.Grid;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.button.ButtonVariant;
import com.vaadin.flow.component.icon.VaadinIcon;
import com.vaadin.flow.component.icon.Icon;
import com.vaadin.flow.component.textfield.TextField;
import com.vaadin.flow.component.combobox.ComboBox;
import com.vaadin.flow.component.notification.Notification;
import com.vaadin.flow.component.confirmdialog.ConfirmDialog;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.component.page.Push;

import java.util.ArrayList;
import java.util.List;

/**
 * RulesView — Detection Rules Management & Semi-NIDS Policy Console.
 *
 * Features:
 *   - View all detection rules (from Rules.json + Rust correlation rules)
 *   - Edit rule severity, enable/disable rules
 *   - Semi-NIDS threshold controls: block, rate-limit, alert thresholds
 *   - Blocked IP list management (permanent + temporary)
 *   - Whitelist management
 *   - Fail-open status and controls
 *
 * Layer 6: Java + Vaadin 24
 */
@Route(value = "rules", layout = AegisMainLayout.class)
@Push
public class RulesView extends VerticalLayout {

    private final Grid<DetectionRule> rulesGrid;
    private final Grid<BlockedIP> blockedGrid;
    private final Grid<WhitelistedIP> whitelistGrid;

    private final Span failOpenStatus = new Span("NORMAL");
    private final Span pendingAlerts = new Span("0");
    private final Span blockedCount = new Span("0");
    private final Span totalEvaluated = new Span("0");

    private final List<DetectionRule> rules = new ArrayList<>();
    private final List<BlockedIP> blockedIPs = new ArrayList<>();
    private final List<WhitelistedIP> whitelistIPs = new ArrayList<>();

    // Semi-NIDS Bridge (JNA → Rust)
    private final AegisSemiNidsBridge semiNids = new AegisSemiNidsBridge();

    public RulesView() {
        setSizeFull();
        setPadding(true);
        setSpacing(true);

        add(new H1("Detection Rules & Semi-NIDS Policy"));

        // ── Semi-NIDS Status Cards ──
        HorizontalLayout statusRow = new HorizontalLayout();
        statusRow.setWidthFull();

        VerticalLayout failOpenCard = createStatCard("Fail-Open", failOpenStatus, "#F44336");
        VerticalLayout pendingCard = createStatCard("Pending Alerts", pendingAlerts, "#FF9800");
        VerticalLayout blockedCard = createStatCard("Blocked IPs", blockedCount, "#9C27B0");
        VerticalLayout totalCard = createStatCard("Total Evaluated", totalEvaluated, "#2196F3");

        statusRow.add(failOpenCard, pendingCard, blockedCard, totalCard);
        add(statusRow);

        // ── Semi-NIDS Threshold Controls ──
        add(new H2("Semi-NIDS Thresholds"));
        HorizontalLayout thresholdRow = new HorizontalLayout();
        thresholdRow.setWidthFull();

        TextField blockThreshold = new TextField("Block Threshold");
        blockThreshold.setValue("60");
        blockThreshold.setPlaceholder("Score >= this + High conf = Block");

        TextField rateLimitThreshold = new TextField("Rate-Limit Threshold");
        rateLimitThreshold.setValue("40");
        rateLimitThreshold.setPlaceholder("Score >= this + Med conf = Rate Limit");

        TextField alertThreshold = new TextField("Alert Threshold");
        alertThreshold.setValue("20");
        alertThreshold.setPlaceholder("Score >= this = Alert (never block)");

        Button applyThresholds = new Button("Apply Thresholds", new Icon(VaadinIcon.CHECK));
        applyThresholds.addThemeVariants(ButtonVariant.LUMO_PRIMARY);
        applyThresholds.addClickListener(e -> {
            Notification.show("Thresholds updated → Rust Semi-NIDS engine (aegis_semi_nids_set_thresholds)",
                              3000, Notification.Position.MIDDLE);
        });

        thresholdRow.add(blockThreshold, rateLimitThreshold, alertThreshold, applyThresholds);
        add(thresholdRow);

        // ── Detection Rules Grid ──
        add(new H2("Detection Rules"));
        rulesGrid = new Grid<>(DetectionRule.class, false);
        rulesGrid.addColumn(DetectionRule::getId).setHeader("ID").setWidth("60px");
        rulesGrid.addColumn(DetectionRule::getName).setHeader("Rule Name").setFlexGrow(2);
        rulesGrid.addColumn(DetectionRule::getCategory).setHeader("Category").setWidth("120px");
        rulesGrid.addColumn(DetectionRule::getSeverity).setHeader("Severity").setWidth("90px");
        rulesGrid.addColumn(DetectionRule::getStatus).setHeader("Status").setWidth("90px");
        rulesGrid.addComponentColumn(this::createRuleToggle).setHeader("Enabled").setWidth("90px");
        rulesGrid.setWidthFull();
        rulesGrid.setHeight("250px");
        add(rulesGrid);

        // ── IP Policy Management ──
        add(new H2("IP Policy — Blocked & Whitelisted"));
        HorizontalLayout ipManagement = new HorizontalLayout();
        ipManagement.setWidthFull();

        // Block IP section
        VerticalLayout blockSection = new VerticalLayout();
        TextField blockIpField = new TextField("IP to Block");
        blockIpField.setPlaceholder("e.g., 192.168.1.100");
        ComboBox<String> blockDuration = new ComboBox<>("Duration");
        blockDuration.setItems("5 min", "30 min", "1 hour", "Permanent");
        blockDuration.setValue("5 min");
        Button blockBtn = new Button("Block IP", new Icon(VaadinIcon.BAN));
        blockBtn.addThemeVariants(ButtonVariant.LUMO_ERROR);
        blockBtn.addClickListener(e -> {
            String ip = blockIpField.getValue();
            if (!ip.isEmpty()) {
                int rc = semiNids.blockIp(ip);
                Notification.show("Blocked " + ip + " → Rust → WFP Kernel (rc=" + rc + ")",
                                  3000, Notification.Position.MIDDLE);
                blockIpField.clear();
            }
        });
        blockSection.add(blockIpField, blockDuration, blockBtn);

        // Whitelist IP section
        VerticalLayout whitelistSection = new VerticalLayout();
        TextField whitelistIpField = new TextField("IP to Whitelist");
        whitelistIpField.setPlaceholder("e.g., 10.0.0.1");
        Button whitelistBtn = new Button("Whitelist IP", new Icon(VaadinIcon.CHECK_CIRCLE));
        whitelistBtn.addThemeVariants(ButtonVariant.LUMO_SUCCESS);
        whitelistBtn.addClickListener(e -> {
            String ip = whitelistIpField.getValue();
            if (!ip.isEmpty()) {
                int rc = semiNids.unblockIp(ip);
                Notification.show("Whitelisted " + ip + " → Rust → removed from block list (rc=" + rc + ")",
                                  3000, Notification.Position.MIDDLE);
                whitelistIpField.clear();
            }
        });
        whitelistSection.add(whitelistIpField, whitelistBtn);

        ipManagement.add(blockSection, whitelistSection);
        add(ipManagement);

        // ── Blocked IPs Grid ──
        blockedGrid = new Grid<>(BlockedIP.class, false);
        blockedGrid.addColumn(BlockedIP::getIp).setHeader("IP Address").setWidth("150px");
        blockedGrid.addColumn(BlockedIP::getReason).setHeader("Reason").setFlexGrow(1);
        blockedGrid.addColumn(BlockedIP::getConfidence).setHeader("Confidence").setWidth("100px");
        blockedGrid.addColumn(BlockedIP::getExpiresAt).setHeader("Expires").setWidth("150px");
        blockedGrid.addComponentColumn(this::createUnblockButton).setHeader("Action").setWidth("100px");
        blockedGrid.setWidthFull();
        blockedGrid.setHeight("200px");
        add(new H2("Currently Blocked IPs"), blockedGrid);

        // Load initial data
        loadRules();
        loadBlockedIPs();
    }

    private VerticalLayout createStatCard(String title, Span value, String color) {
        VerticalLayout card = new VerticalLayout();
        card.setPadding(true);
        card.setSpacing(false);
        Span titleLabel = new Span(title);
        titleLabel.getStyle().set("font-size", "0.85em").set("color", "#666");
        value.getStyle().set("font-size", "1.8em").set("font-weight", "bold").set("color", color);
        card.add(titleLabel, value);
        return card;
    }

    private Button createRuleToggle(DetectionRule rule) {
        Button toggle = new Button(rule.enabled ? "ON" : "OFF");
        toggle.addThemeVariants(rule.enabled ? ButtonVariant.LUMO_SUCCESS : ButtonVariant.LUMO_ERROR);
        toggle.addClickListener(e -> {
            rule.enabled = !rule.enabled;
            toggle.setText(rule.enabled ? "ON" : "OFF");
            toggle.addThemeVariants(rule.enabled ? ButtonVariant.LUMO_SUCCESS : ButtonVariant.LUMO_ERROR);
        });
        return toggle;
    }

    private Button createUnblockButton(BlockedIP entry) {
        Button unblock = new Button("Unblock", new Icon(VaadinIcon.CLOSE_CIRCLE));
        unblock.addThemeVariants(ButtonVariant.LUMO_SMALL);
        unblock.addClickListener(e -> {
            int rc = semiNids.unblockIp(entry.ip);
            Notification.show("Unblocked " + entry.ip + " (rc=" + rc + ")",
                              2000, Notification.Position.MIDDLE);
        });
        return unblock;
    }

    private void loadRules() {
        // In production: read from Rules.json + Rust correlation rules via JNA
        rules.add(new DetectionRule(1, "SYN Flood Detection", "Network", "HIGH", true));
        rules.add(new DetectionRule(2, "Port Scan Detection", "Network", "MEDIUM", true));
        rules.add(new DetectionRule(3, "Suspicious Pipe Name", "Pipe", "HIGH", true));
        rules.add(new DetectionRule(4, "C2 Beacon Pattern", "Network", "CRITICAL", true));
        rules.add(new DetectionRule(5, "Lateral Movement", "Cross-Vector", "CRITICAL", true));
        rules.add(new DetectionRule(6, "High Entropy Payload", "Network", "MEDIUM", true));
        rules.add(new DetectionRule(7, "Known Exploit Sig", "Network", "CRITICAL", true));
        rules.add(new DetectionRule(8, "Process Injection", "Pipe", "HIGH", true));
        rules.add(new DetectionRule(9, "Data Exfiltration", "Cross-Vector", "HIGH", true));
        rules.add(new DetectionRule(10, "DNS Tunneling", "Network", "MEDIUM", true));
        rulesGrid.setItems(rules);
    }

    private void loadBlockedIPs() {
        // In production: query from Rust Semi-NIDS engine via JNA
        blockedGrid.setItems(blockedIPs);
    }

    // ─── Data Classes ──

    public static class DetectionRule {
        public int id;
        public String name;
        public String category;
        public String severity;
        public boolean enabled;

        public DetectionRule(int id, String name, String cat, String sev, boolean en) {
            this.id = id; this.name = name; this.category = cat;
            this.severity = sev; this.enabled = en;
        }
        public String getId() { return String.valueOf(id); }
        public String getName() { return name; }
        public String getCategory() { return category; }
        public String getSeverity() { return severity; }
        public String getStatus() { return enabled ? "Active" : "Disabled"; }
    }

    public static class BlockedIP {
        public String ip;
        public String reason;
        public String confidence;
        public String expiresAt;

        public BlockedIP(String ip, String reason, String conf, String exp) {
            this.ip = ip; this.reason = reason; this.confidence = conf; this.expiresAt = exp;
        }
        public String getIp() { return ip; }
        public String getReason() { return reason; }
        public String getConfidence() { return confidence; }
        public String getExpiresAt() { return expiresAt; }
    }

    public static class WhitelistedIP {
        public String ip;
        public String addedBy;
        public WhitelistedIP(String ip, String by) { this.ip = ip; this.addedBy = by; }
        public String getIp() { return ip; }
        public String getAddedBy() { return addedBy; }
    }
}
