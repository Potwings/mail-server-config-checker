package io.github.potwings.mailcheck.api;

import java.util.List;

/**
 * Input for a diagnosis run.
 *
 * @param domain         normalized (punycode, lowercase) target domain
 * @param targetIps      IPs used by PTR/RBL checks; empty when none could be determined
 * @param targetIpSource human-readable origin of targetIps (user input vs. derived from MX)
 */
public record CheckContext(String domain, List<String> targetIps, String targetIpSource) {

    public CheckContext {
        targetIps = targetIps == null ? List.of() : List.copyOf(targetIps);
    }

    public boolean hasTargetIps() {
        return !targetIps.isEmpty();
    }
}
