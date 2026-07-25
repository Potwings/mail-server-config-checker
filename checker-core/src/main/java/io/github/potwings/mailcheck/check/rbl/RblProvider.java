package io.github.potwings.mailcheck.check.rbl;

import io.github.potwings.mailcheck.dns.DnsAnswer;

/**
 * One RBL source. Abstracted from day one so zones can be added/removed and a
 * commercial source (e.g. paid Spamhaus subscription) can be swapped in without
 * touching the check logic.
 */
public interface RblProvider {

    String name();

    /** False when required configuration (e.g. DQS key) is missing — check reports SKIP with guidance. */
    boolean enabled();

    /** Reason shown to the user when {@link #enabled()} is false. */
    default String disabledReason() {
        return "비활성화됨";
    }

    /** Full query FQDN for a reversed IP (IPv4 octets "4.3.2.1", IPv6 nibbles "1.0....2"). */
    String queryName(String reversedIp);

    /** True when the zone also lists IPv6 addresses (nibble-format queries). */
    default boolean supportsIpv6() {
        return false;
    }

    /** Maps the DNS answer for {@link #queryName} to a verdict. */
    RblVerdict interpret(DnsAnswer answer);
}
