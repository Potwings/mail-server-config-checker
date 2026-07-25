package io.github.potwings.mailcheck.web.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.List;

@ConfigurationProperties(prefix = "mailcheck")
public record MailcheckProperties(
        Duration dnsTimeout,
        Duration checkTimeout,
        Rbl rbl,
        List<String> propagationResolvers) {

    public record Rbl(String spamhausDqsKey, boolean barracudaEnabled, boolean spamcopEnabled,
                      boolean psblEnabled, boolean mailspikeEnabled, boolean hostkarmaEnabled) {
    }
}
