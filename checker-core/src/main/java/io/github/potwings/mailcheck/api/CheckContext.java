package io.github.potwings.mailcheck.api;

import java.util.List;

/**
 * Input for a diagnosis run.
 *
 * @param domain          normalized (punycode, lowercase) target domain
 * @param targetIps       IPs used by PTR/RBL checks; empty when none could be determined
 * @param targetIpSource  human-readable origin of targetIps (user input vs. derived from MX)
 * @param ipsUserProvided true only when targetIps came from user input — SPF check_host
 *                        evaluation runs only then (MX-derived inbound IPs are not the
 *                        outbound IPs, so evaluating them would mislead)
 */
public record CheckContext(String domain, List<String> targetIps, String targetIpSource,
                           boolean ipsUserProvided) {

    public CheckContext {
        targetIps = targetIps == null ? List.of() : List.copyOf(targetIps);
    }

    public CheckContext(String domain, List<String> targetIps, String targetIpSource) {
        this(domain, targetIps, targetIpSource, false);
    }

    public boolean hasTargetIps() {
        return !targetIps.isEmpty();
    }
}
