package io.github.potwings.mailcheck.web.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.List;

@ConfigurationProperties(prefix = "mailcheck")
public record MailcheckProperties(
        Duration dnsTimeout,
        Duration checkTimeout,
        Duration mtaStsHttpTimeout,
        Rbl rbl,
        List<String> propagationResolvers,
        Intake intake) {

    public record Rbl(String spamhausDqsKey, boolean barracudaEnabled, boolean spamcopEnabled,
                      boolean psblEnabled, boolean mailspikeEnabled, boolean hostkarmaEnabled) {
    }

    /**
     * Real-mail pipeline settings.
     *
     * @param mailDomain domain of issued test addresses (check-{uuid}@mailDomain)
     * @param sessionTtl acceptance window for incoming mail; results are kept past it
     */
    public record Intake(boolean enabled, String incomingDir, String dataDir, String mailDomain,
                         Duration pollInterval, Duration sessionTtl) {
    }
}
