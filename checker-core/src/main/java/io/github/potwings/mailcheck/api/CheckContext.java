package io.github.potwings.mailcheck.api;

/**
 * Input for a diagnosis run.
 *
 * @param domain         normalized (punycode, lowercase) target domain
 * @param targetIp       IP used by PTR/RBL checks; null when it could not be determined
 * @param targetIpSource human-readable origin of targetIp (user input vs. derived from MX)
 */
public record CheckContext(String domain, String targetIp, String targetIpSource) {

    public boolean hasTargetIp() {
        return targetIp != null && !targetIp.isBlank();
    }
}
