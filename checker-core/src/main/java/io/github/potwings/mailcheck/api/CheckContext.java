package io.github.potwings.mailcheck.api;

import java.util.List;
import java.util.Locale;

/**
 * Input for a diagnosis run.
 *
 * @param domain          normalized (punycode, lowercase) target domain
 * @param targetIps       IPs used by PTR/RBL checks; empty when none could be determined
 * @param targetIpSource  human-readable origin of targetIps (user input vs. derived from MX)
 * @param ipsUserProvided true only when targetIps came from user input — SPF check_host
 *                        evaluation runs only then (MX-derived inbound IPs are not the
 *                        outbound IPs, so evaluating them would mislead)
 * @param mailSession     SMTP session values captured from a real test mail; null when the
 *                        diagnosis was not triggered by a received mail
 */
public record CheckContext(String domain, List<String> targetIps, String targetIpSource,
                           boolean ipsUserProvided, MailSession mailSession) {

    /**
     * Envelope values from the live SMTP session that delivered the test mail.
     *
     * @param mailFrom envelope MAIL FROM address; null/blank for a bounce (null sender)
     * @param helo     HELO/EHLO name as claimed by the client
     */
    public record MailSession(String mailFrom, String helo) {

        /** RFC 5321 null reverse-path (bounce): no usable MAIL FROM. */
        public boolean bounce() {
            return mailFrom == null || mailFrom.isBlank();
        }

        /** Domain after the last '@' of MAIL FROM; null when bounce or no '@'. */
        public String mailFromDomain() {
            if (bounce()) {
                return null;
            }
            int at = mailFrom.lastIndexOf('@');
            if (at < 0 || at == mailFrom.length() - 1) {
                return null;
            }
            return mailFrom.substring(at + 1).toLowerCase(Locale.ROOT);
        }
    }

    public CheckContext {
        targetIps = targetIps == null ? List.of() : List.copyOf(targetIps);
    }

    public CheckContext(String domain, List<String> targetIps, String targetIpSource,
                        boolean ipsUserProvided) {
        this(domain, targetIps, targetIpSource, ipsUserProvided, null);
    }

    public CheckContext(String domain, List<String> targetIps, String targetIpSource) {
        this(domain, targetIps, targetIpSource, false, null);
    }

    public boolean hasTargetIps() {
        return !targetIps.isEmpty();
    }

    public boolean hasMailSession() {
        return mailSession != null;
    }
}
