package io.github.potwings.mailcheck.check.tlspolicy;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

public class HttpPolicyFetcher implements PolicyFetcher {

    private static final int MAX_BODY_BYTES = 65536;

    private final HttpClient client;
    private final Duration timeout;

    public HttpPolicyFetcher(Duration timeout) {
        this.timeout = timeout;
        this.client = HttpClient.newBuilder()
                .connectTimeout(timeout)
                // RFC 8461 §3.3 — senders must not follow redirects when fetching the policy.
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    @Override
    public String fetch(String domain) throws IOException, InterruptedException {
        URI uri = URI.create("https://mta-sts." + domain + "/.well-known/mta-sts.txt");
        HttpRequest request = HttpRequest.newBuilder(uri).timeout(timeout).GET().build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IOException("HTTP " + response.statusCode());
        }
        if (response.body().length() > MAX_BODY_BYTES) {
            throw new IOException("정책 파일이 비정상적으로 큼 (" + response.body().length() + " bytes)");
        }
        return response.body();
    }
}
