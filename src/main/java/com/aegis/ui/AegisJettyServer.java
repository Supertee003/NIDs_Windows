package com.aegis.ui;

import com.vaadin.flow.server.VaadinServlet;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.webapp.WebAppContext;

/**
 * AegisJettyServer — Embedded Jetty launcher for AEGIS NIDS Web UI.
 *
 * Monolithic deployment — no external Tomcat/WildFly needed.
 * Starts Jetty on port 8443 with Vaadin 24 servlet.
 *
 * Layer 6: Java + Vaadin 24
 * Language: Java 17+
 */
public class AegisJettyServer {

    private static final int DEFAULT_PORT = 8443;

    public static void main(String[] args) throws Exception {
        int port = DEFAULT_PORT;
        if (args.length > 0) {
            try {
                port = Integer.parseInt(args[0]);
            } catch (NumberFormatException e) {
                System.err.println("Invalid port, using default: " + DEFAULT_PORT);
            }
        }

        System.out.println("═══════════════════════════════════════════");
        System.out.println("  AEGIS NIDS — Web UI Server (Vaadin 24)");
        System.out.println("  Embedded Jetty on port " + port);
        System.out.println("═══════════════════════════════════════════");

        Server server = new Server(port);

        WebAppContext context = new WebAppContext();
        context.setContextPath("/");
        context.setResourceBase("src/main/resources");
        context.setClassLoader(Thread.currentThread().getContextClassLoader());

        // Register Vaadin servlet
        ServletHolder vaadinHolder = new ServletHolder(new VaadinServlet());
        vaadinHolder.setInitParameter("productionMode", "true");
        context.addServlet(vaadinHolder, "/*");

        server.setHandler(context);

        try {
            server.start();
            System.out.println("AEGIS Web UI available at: https://localhost:" + port);
            server.join();
        } finally {
            server.stop();
        }
    }
}
