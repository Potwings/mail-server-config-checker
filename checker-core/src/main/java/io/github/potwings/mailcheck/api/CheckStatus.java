package io.github.potwings.mailcheck.api;

/**
 * Verdict of a single check. Ordered by severity so aggregation can keep the worst status.
 */
public enum CheckStatus {
    PASS(0),
    SKIP(1),
    WARN(2),
    ERROR(3),
    FAIL(4);

    private final int severity;

    CheckStatus(int severity) {
        this.severity = severity;
    }

    public boolean isWorseThan(CheckStatus other) {
        return this.severity > other.severity;
    }
}
