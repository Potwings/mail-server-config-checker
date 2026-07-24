package io.github.potwings.mailcheck.api;

/**
 * A single diagnostic unit. Implementations must be stateless and thread-safe:
 * the engine runs all checks concurrently against the same context.
 */
public interface Check {

    /** Stable identifier used in API responses (e.g. "spf", "dmarc"). */
    String id();

    /** Human-readable title shown in the UI. */
    String title();

    CheckResult run(CheckContext context);
}
