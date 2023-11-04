package com.wingmann.sslipscanner;

import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ConnectTimeoutException;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.HttpContext;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class ThreadedAddrScan extends Thread {
    private static final String PEER_CERTIFICATES = "PEER_CERTIFICATES";
    private final CloseableHttpClient httpClient;
    private final RequestConfig requestConfig;
    private final List<String> ips;
    private List<String> domains;
    private int scansFinishedCount = 0;

    public ThreadedAddrScan(CloseableHttpClient httpClient, RequestConfig requestConfig, List<String> ips) {
        this.httpClient = httpClient;
        this.requestConfig = requestConfig;
        this.ips = ips;
    }

    public List<String> getDomains() {
        return domains;
    }

    public int getScansFinishedCount() {
        return scansFinishedCount;
    }

    @Override
    public void run() {
        domains = new ArrayList<String>();

        for (String ip : ips) {
            try {
                scansFinishedCount++;

                // Creating request.
                HttpGet httpget = new HttpGet(String.format("https://%s", ip));
                httpget.setConfig(requestConfig);

                HttpContext context = new BasicHttpContext();
                httpClient.execute(httpget, context);

                // Get certificates.
                Certificate[] peerCertificates = (Certificate[]) context.getAttribute(PEER_CERTIFICATES);

                for (Certificate certificate : peerCertificates) {
                    X509Certificate real = (X509Certificate) certificate;
                    Collection<List<?>> subjectAlternativeNames = real.getSubjectAlternativeNames();

                    if (subjectAlternativeNames != null) {
                        for (List<?> san : subjectAlternativeNames) {
                            if (san.get(0).equals(2)) {
                                domains.add(san.get(1).toString());
                                System.out.printf("Domain: %s", san.get(1));
                            }
                        }
                    }
                }
            } catch (ConnectTimeoutException e) {
                System.err.printf("%s: Connection timeout%n", ip);
            } catch (Exception e) {
                System.err.printf("%s: %s%n", ip, e.getMessage());
            }
        }
    }
}
