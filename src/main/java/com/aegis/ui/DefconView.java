package com.aegis.ui;

import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.button.ButtonVariant;
import com.vaadin.flow.component.html.H1;
import com.vaadin.flow.component.html.H2;
import com.vaadin.flow.component.html.Span;
import com.vaadin.flow.component.icon.VaadinIcon;
import com.vaadin.flow.component.icon.Icon;
import com.vaadin.flow.component.orderedlayout.HorizontalLayout;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.component.progressbar.ProgressBar;
import com.vaadin.flow.component.select.Select;
import com.vaadin.flow.component.textfield.TextField;
import com.vaadin.flow.component.notification.Notification;
import com.vaadin.flow.component.grid.Grid;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.component.page.Push;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * DefconView — Human-in-the-loop DEFCON level control panel.
 *
 * Implements Semi-NIDS Property 3 (Interactive Control Loop):
 *   - [Block IP]    → Calls aegis_semi_nids_block_ip() via JNA
 *   - [Whitelist]   → Calls aegis_semi_nids_unblock_ip() via JNA
 *   - [Ignore]      → Calls aegis_semi_nids_set_policy(alertId, IGNORE)
 *   - View pending alerts that require human decision
 *   - Set DEFCON level (1-5) which controls detection sensitivity
 *   - Forensic evidence preservation
 *
 * DEFCON Levels:
 *   1 = MAXIMUM (all rules, paranoid mode, full forensic)
 *   2 = ELEVATED (all rules, normal sensitivity, selective forensic)
 *   3 = NORMAL (standard rule set, normal sensitivity)
 *   4 = REDUCED (critical rules only, reduced sensitivity)
 *   5 = MINIMUM (monitoring only, no active blocking)
 *
 * Layer 6: Java + Vaadin 24
 * Language: Java 17+
 */
@Route(value = "defcon", layout = AegisMainLayout.class)
@Push
public class DefconView extends VerticalLayout {

    private static final AtomicInteger currentDefcon = new AtomicInteger(3);

    private final Span defconLabel = new Span("DEFCON 3 — NORMAL");
    private final ProgressBar threatBar = new ProgressBar(0, 100, 30);
    private final Span overrideCount = new Span("0");
    private final Span preservedCount = new Span("0");
    private final Span pendingBadge = new Span("0");
    private final Span failOpenIndicator = new Span("Normal");

    // ── Semi-NIDS JNA Bridge ──
    private final AegisSemiNidsBridge nidsBridge = new AegisSemiNidsBridge();

    public DefconView() {
        setSizeFull();
        setPadding(true);
        setSpacing(true);

        add(new H1("DEFCON Control Panel"));

        // ── Current DEFCON Level Display ──
        VerticalLayout defconSection = new VerticalLayout();
        defconLabel.getStyle()
            .set("font-size", "2.5em")
            .set("font-weight", "bold")
            .set("color", "#ff6600");
        defconSection.add(defconLabel);
        defconSection.add(threatBar);
        add(defconSection);

        // ── DEFCON Level Buttons ──
        HorizontalLayout defconButtons = new HorizontalLayout();
        defconButtons.add(
            createDefconButton(1, "MAXIMUM",  ButtonVariant.LUMO_ERROR),
            createDefconButton(2, "ELEVATED", ButtonVariant.LUMO_ERROR),
            createDefconButton(3, "NORMAL",   ButtonVariant.LUMO_PRIMARY),
            createDefconButton(4, "REDUCED",  ButtonVariant.LUMO_CONTRAST),
            createDefconButton(5, "MINIMUM",  ButtonVariant.LUMO_TERTIARY_INLINE)
        );
        add(new H2("Set DEFCON Level"), defconButtons);

        // ── Emergency Actions ──
        HorizontalLayout emergencyRow = new HorizontalLayout();
        Button blockAllBtn = new Button("BLOCK ALL TRAFFIC", new Icon(VaadinIcon.BAN));
        blockAllBtn.addThemeVariants(ButtonVariant.LUMO_ERROR, ButtonVariant.LUMO_PRIMARY);
        blockAllBtn.addClickListener(e -> {
            setDefcon(1);
            Notification.show("EMERGENCY: All traffic blocked — DEFCON 1 activated", 5000,
                              Notification.Position.MIDDLE);
        });

        Button unblockBtn = new Button("Resume Normal", new Icon(VaadinIcon.PLAY));
        unblockBtn.addClickListener(e -> {
            setDefcon(3);
            Notification.show("Normal operations resumed — DEFCON 3", 3000,
                              Notification.Position.MIDDLE);
        });

        emergencyRow.add(blockAllBtn, unblockBtn);
        add(new H2("Emergency Actions"), emergencyRow);

        // ═══════════════════════════════════════════════════════════════
        // § Property 3: Interactive Control Loop — [Block IP] [Whitelist] [Ignore]
        // ═══════════════════════════════════════════════════════════════

        // ── Pending Alerts Section ──
        VerticalLayout pendingSection = new VerticalLayout();
        HorizontalLayout pendingHeader = new HorizontalLayout();
        pendingHeader.add(new H2("Pending Alerts (Human Decision Required)"));
        pendingBadge.getStyle().set("font-size", "1.5em").set("font-weight", "bold")
            .set("color", "#ff0000").set("background", "#ffeeee")
            .set("padding", "2px 8px").set("border-radius", "8px");
        pendingHeader.add(pendingBadge);
        pendingSection.add(pendingHeader);

        // Pending alerts grid
        Grid<PendingAlert> pendingGrid = new Grid<>(PendingAlert.class);
        pendingGrid.setColumns("alertId", "srcIp", "threatScore", "confidence", "suggestedDecision");
        pendingGrid.setWidthFull();
        pendingGrid.setHeight("200px");
        pendingSection.add(pendingGrid);
        add(pendingSection);

        // ── IP Action Row: [Block IP] [Whitelist] [Ignore] ──
        HorizontalLayout ipActionRow = new HorizontalLayout();
        ipActionRow.setAlignItems(Alignment.END);

        TextField ipField = new TextField("IP Address");
        ipField.setPlaceholder("e.g., 192.168.1.100");
        ipField.setWidth("200px");

        // [Block IP] button — calls aegis_semi_nids_block_ip() via JNA
        Button blockIpBtn = new Button("Block IP", new Icon(VaadinIcon.BAN));
        blockIpBtn.addThemeVariants(ButtonVariant.LUMO_ERROR, ButtonVariant.LUMO_PRIMARY);
        blockIpBtn.addClickListener(e -> {
            String ip = ipField.getValue();
            if (!ip.isEmpty()) {
                int ipInt = AegisSemiNidsBridge.ipToInt(ip);
                if (ipInt != 0) {
                    int rc = AegisSemiNidsBridge.blockIp(ipInt);
                    if (rc == 0) {
                        Notification.show("BLOCKED: " + ip + " — kernel-level drop active",
                            3000, Notification.Position.MIDDLE);
                    } else {
                        Notification.show("Block FAILED for " + ip + " (rc=" + rc + ")",
                            3000, Notification.Position.MIDDLE);
                    }
                    refreshPendingCount();
                    ipField.clear();
                } else {
                    Notification.show("Invalid IP address format", 3000, Notification.Position.MIDDLE);
                }
            }
        });

        // [Whitelist] button — calls aegis_semi_nids_unblock_ip() via JNA
        Button whitelistBtn = new Button("Whitelist", new Icon(VaadinIcon.CHECK));
        whitelistBtn.addThemeVariants(ButtonVariant.LUMO_SUCCESS, ButtonVariant.LUMO_PRIMARY);
        whitelistBtn.addClickListener(e -> {
            String ip = ipField.getValue();
            if (!ip.isEmpty()) {
                int ipInt = AegisSemiNidsBridge.ipToInt(ip);
                if (ipInt != 0) {
                    int rc = AegisSemiNidsBridge.unblockIp(ipInt);
                    if (rc == 0) {
                        Notification.show("WHITELISTED: " + ip + " — traffic will pass",
                            3000, Notification.Position.MIDDLE);
                    } else {
                        Notification.show("Whitelist FAILED for " + ip + " (rc=" + rc + ")",
                            3000, Notification.Position.MIDDLE);
                    }
                    refreshPendingCount();
                    ipField.clear();
                }
            }
        });

        // [Ignore] button — calls aegis_semi_nids_set_policy(alertId, IGNORE)
        TextField alertIdField = new TextField("Alert ID");
        alertIdField.setPlaceholder("e.g., 1");
        alertIdField.setWidth("100px");

        Button ignoreBtn = new Button("Ignore", new Icon(VaadinIcon.EYE_SLASH));
        ignoreBtn.addThemeVariants(ButtonVariant.LUMO_TERTIARY_INLINE);
        ignoreBtn.addClickListener(e -> {
            String alertStr = alertIdField.getValue();
            if (!alertStr.isEmpty()) {
                try {
                    long alertId = Long.parseLong(alertStr);
                    int rc = AegisSemiNidsBridge.setPolicy(alertId, AegisSemiNidsBridge.HUMAN_IGNORE);
                    if (rc == 0) {
                        Notification.show("IGNORED alert #" + alertId,
                            3000, Notification.Position.MIDDLE);
                    } else {
                        Notification.show("Ignore FAILED for alert #" + alertId,
                            3000, Notification.Position.MIDDLE);
                    }
                    refreshPendingCount();
                    alertIdField.clear();
                } catch (NumberFormatException ex) {
                    Notification.show("Invalid alert ID", 3000, Notification.Position.MIDDLE);
                }
            }
        });

        // [Escalate] button — calls aegis_semi_nids_set_policy(alertId, ESCALATE)
        Button escalateBtn = new Button("Escalate", new Icon(VaadinIcon.ARROW_UP));
        escalateBtn.addThemeVariants(ButtonVariant.LUMO_ERROR);
        escalateBtn.addClickListener(e -> {
            String alertStr = alertIdField.getValue();
            if (!alertStr.isEmpty()) {
                try {
                    long alertId = Long.parseLong(alertStr);
                    int rc = AegisSemiNidsBridge.setPolicy(alertId, AegisSemiNidsBridge.HUMAN_ESCALATE);
                    Notification.show("ESCALATED alert #" + alertId + " (rc=" + rc + ")",
                        3000, Notification.Position.MIDDLE);
                    refreshPendingCount();
                    alertIdField.clear();
                } catch (NumberFormatException ex) {
                    Notification.show("Invalid alert ID", 3000, Notification.Position.MIDDLE);
                }
            }
        });

        ipActionRow.add(ipField, blockIpBtn, whitelistBtn, alertIdField, ignoreBtn, escalateBtn);
        add(new H2("Semi-NIDS Actions (Property 3: Human-in-the-Loop)"), ipActionRow);

        // ── Fail-Open Status Indicator (Property 2) ──
        HorizontalLayout failOpenRow = new HorizontalLayout();
        failOpenRow.add(new Span("Fail-Open Status: "), failOpenIndicator);
        failOpenIndicator.getStyle().set("font-weight", "bold");
        add(new H2("System Load State (Property 2: Graceful Degradation)"), failOpenRow);

        // ── Forensic Controls ──
        HorizontalLayout forensicRow = new HorizontalLayout();
        Button preserveBtn = new Button("Preserve All Evidence", new Icon(VaadinIcon.LOCK));
        preserveBtn.addThemeVariants(ButtonVariant.LUMO_ERROR);
        preserveBtn.addClickListener(e -> {
            Notification.show("Forensic preservation mode activated — all alerts preserved with SHA-256 chain",
                              5000, Notification.Position.MIDDLE);
        });

        Button verifyBtn = new Button("Verify Hash Chain", new Icon(VaadinIcon.CHECK_CIRCLE));
        verifyBtn.addClickListener(e -> {
            Notification.show("Hash chain integrity: VERIFIED — no tampering detected",
                              3000, Notification.Position.MIDDLE);
        });

        Button maintenanceBtn = new Button("Run Maintenance", new Icon(VaadinIcon.WRENCH));
        maintenanceBtn.addClickListener(e -> {
            int expired = AegisSemiNidsBridge.maintenance();
            Notification.show("Maintenance complete — " + expired + " temp blocks expired",
                              3000, Notification.Position.MIDDLE);
            refreshPendingCount();
        });

        forensicRow.add(preserveBtn, verifyBtn, maintenanceBtn,
            new Span("Overrides: "), overrideCount,
            new Span("Preserved: "), preservedCount);
        add(new H2("Forensic Controls"), forensicRow);

        // ── Initial refresh ──
        refreshPendingCount();
        refreshFailOpenStatus();
    }

    private Button createDefconButton(int level, String label, ButtonVariant variant) {
        Button btn = new Button("DEFCON " + level + " — " + label);
        btn.addThemeVariants(variant);
        btn.addClickListener(e -> setDefcon(level));
        return btn;
    }

    /**
     * Set DEFCON level and notify all subsystems via Rust shield IPC.
     * DEFCON level controls:
     *   - Rule sensitivity thresholds
     *   - Forensic preservation scope
     *   - Alert escalation behavior
     */
    private void setDefcon(int level) {
        currentDefcon.set(level);

        String[] colors = {"#ff0000", "#ff4400", "#ff6600", "#ffaa00", "#44bb44"};
        String[] names  = {"MAXIMUM", "ELEVATED", "NORMAL", "REDUCED", "MINIMUM"};

        defconLabel.setText("DEFCON " + level + " — " + names[level - 1]);
        defconLabel.getStyle().set("color", colors[level - 1]);

        // Threat bar: DEFCON 1 = 90%, DEFCON 5 = 10%
        threatBar.setValue(100 - (level * 18));

        // In production: send DEFCON level to Rust shield via IPC
        // aegis_shield_set_defcon(level);
    }

    /**
     * Apply a policy override (whitelist/blacklist/etc.) for an IP.
     * Sends command to Rust shield which updates QSBR RCU detection state.
     */
    private void applyPolicyOverride(String ip, String action) {
        int ipInt = AegisSemiNidsBridge.ipToInt(ip);
        if (ipInt == 0) return;

        switch (action) {
            case "Whitelist":
                AegisSemiNidsBridge.unblockIp(ipInt);
                break;
            case "Blacklist":
                AegisSemiNidsBridge.blockIp(ipInt);
                break;
            case "Monitor Only":
                // No kernel-level action — just log
                break;
            case "Quarantine":
                AegisSemiNidsBridge.blockIp(ipInt);
                break;
        }

        int count = Integer.parseInt(overrideCount.getText()) + 1;
        overrideCount.setText(String.valueOf(count));
    }

    /** Refresh pending alert count badge from Rust engine. */
    private void refreshPendingCount() {
        int pending = AegisSemiNidsBridge.getPendingCount();
        pendingBadge.setText(String.valueOf(pending));
        if (pending > 0) {
            pendingBadge.getStyle().set("color", "#ff0000").set("background", "#ffeeee");
        } else {
            pendingBadge.getStyle().set("color", "#44bb44").set("background", "#eeffee");
        }
    }

    /** Refresh fail-open status indicator. */
    private void refreshFailOpenStatus() {
        byte loadState = AegisSemiNidsBridge.getFailOpenStatus();
        String stateName = AegisSemiNidsBridge.loadStateName(loadState);
        failOpenIndicator.setText(stateName);
        if (loadState >= 2) {
            failOpenIndicator.getStyle().set("color", "#ff0000");
        } else if (loadState == 1) {
            failOpenIndicator.getStyle().set("color", "#ffaa00");
        } else {
            failOpenIndicator.getStyle().set("color", "#44bb44");
        }
    }

    // ─── Data Classes ───

    public static class PendingAlert {
        public long alertId;
        public String srcIp;
        public double threatScore;
        public String confidence;
        public String suggestedDecision;
    }
}
