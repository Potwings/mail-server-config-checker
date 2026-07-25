package io.github.potwings.mailcheck.check.rbl;

import io.github.potwings.mailcheck.dns.DnsAnswer;

/**
 * One domain-based RBL source (queries the domain name itself, not an IP).
 * Same abstraction rationale as {@link RblProvider}: zones (e.g. SURBL, URIBL)
 * can be added without touching the check logic.
 */
public interface DomainRblProvider {

    String name();

    /** False when required configuration (e.g. DQS key) is missing — check reports SKIP with guidance. */
    boolean enabled();

    /** Reason shown to the user when {@link #enabled()} is false. */
    default String disabledReason() {
        return "비활성화됨";
    }

    /** Full query FQDN for the target domain (e.g. "example.com"). */
    String queryName(String domain);

    /** Maps the DNS answer for {@link #queryName} to a verdict. */
    RblVerdict interpret(DnsAnswer answer);
}
