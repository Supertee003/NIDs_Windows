package com.aegis.ui;

import com.vaadin.flow.server.PWA;
import com.vaadin.flow.component.page.Viewport;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.component.applayout.AppLayout;
import com.vaadin.flow.component.applayout.DrawerToggle;
import com.vaadin.flow.component.html.Span;
import com.vaadin.flow.component.icon.VaadinIcon;
import com.vaadin.flow.component.icon.Icon;
import com.vaadin.flow.component.tabs.Tab;
import com.vaadin.flow.component.tabs.Tabs;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;

/**
 * AegisMainLayout — Root layout for AEGIS NIDS Vaadin 24 Web UI.
 *
 * Embedded Jetty monolithic architecture — no external server needed.
 * Provides navigation between DashboardView and DefconView.
 *
 * Layer 6: Java + Vaadin 24
 * Language: Java 17+
 */
@PWA(name = "AEGIS NIDS", shortName = "AEGIS")
@Viewport("width=device-width, initial-scale=1")
public class AegisMainLayout extends AppLayout {

    private final Tabs tabs;

    public AegisMainLayout() {
        setPrimarySection(Section.DRAWER);

        // Header
        addToNavbar(new DrawerToggle());
        addToNavbar(new Span("  AEGIS NIDS — Network Intrusion Detection System"));

        // Navigation tabs
        Tab dashboardTab = new Tab(VaadinIcon.DASHBOARD.create(), new Span("Dashboard"));
        Tab defconTab    = new Tab(VaadinIcon.SHIELD.create(), new Span("DEFCON Control"));
        Tab forensicTab  = new Tab(VaadinIcon.LOCK.create(), new Span("Forensics"));
        Tab rulesTab     = new Tab(VaadinIcon.COG.create(), new Span("Rules"));

        tabs = new Tabs(dashboardTab, defconTab, forensicTab, rulesTab);
        tabs.setOrientation(Tabs.Orientation.VERTICAL);
        addToDrawer(tabs);

        // Tab → Route mapping
        tabs.addSelectedChangeListener(event -> {
            Tab selected = event.getSelectedTab();
            if (selected == dashboardTab) {
                navigateTo("dashboard");
            } else if (selected == defconTab) {
                navigateTo("defcon");
            } else if (selected == forensicTab) {
                navigateTo("forensics");
            } else if (selected == rulesTab) {
                navigateTo("rules");
            }
        });
    }

    private void navigateTo(String route) {
        getUI().ifPresent(ui -> ui.navigate(route));
    }
}
