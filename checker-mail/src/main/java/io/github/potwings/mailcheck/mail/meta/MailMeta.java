package io.github.potwings.mailcheck.mail.meta;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.OffsetDateTime;
import java.util.Locale;

/**
 * Mirror of the collector's meta.json (infra-work.md §3.3). Trust levels differ
 * per field: client_ip is observed from TCP and trustworthy; helo/mail_from are
 * sender-claimed values under verification.
 */
public record MailMeta(
        @JsonProperty("received_at") OffsetDateTime receivedAt,
        @JsonProperty("queue_id") String queueId,
        @JsonProperty("client_ip") String clientIp,
        @JsonProperty("client_hostname") String clientHostname,
        @JsonProperty("client_port") String clientPort,
        @JsonProperty("client_protocol") String clientProtocol,
        @JsonProperty("helo") String helo,
        @JsonProperty("mail_from") String mailFrom,
        @JsonProperty("rcpt_to") String rcptTo,
        @JsonProperty("original_rcpt_to") String originalRcptTo,
        @JsonProperty("size_reported") String sizeReported,
        @JsonProperty("size_actual") Long sizeActual) {

    /** Lowercased local part of rcpt_to (the diagnosis token); null when absent. */
    public String rcptLocalPart() {
        if (rcptTo == null) {
            return null;
        }
        int at = rcptTo.lastIndexOf('@');
        if (at <= 0) {
            return null;
        }
        return rcptTo.substring(0, at).toLowerCase(Locale.ROOT);
    }
}
