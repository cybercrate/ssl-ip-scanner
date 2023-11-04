package com.wingmann.sslipscanner;

import io.javalin.Javalin;

import java.util.Objects;

public class Main {
    public static void main(String[] args) {
        Javalin app = Javalin.create().start(8080);
        String htmlSource = "html/index.html";

        app.get("/", context -> context.render(htmlSource));

        app.post("/scan", context -> {
            System.out.println("New request");
            String ip = context.formParam("ip");

            int threadCount = Integer.parseInt(Objects.requireNonNull(context.formParam("threads")));

            if (threadCount < 1) {
                threadCount = Thread.activeCount();
            }

            try {
                AddrScanner scanner = new AddrScanner();

                try {
                    scanner.scan(ip, threadCount);
                } catch (Exception e) {
                    System.err.println(e.getMessage());
                    scanner.terminateClient();
                    context.status(500);
                } finally {
                    scanner.terminateClient();
                    context.render(htmlSource);
                }
            } catch (Exception e) {
                System.err.println(e.getMessage());
                context.status(500);
            }

            context.status(200);
        });
    }
}
