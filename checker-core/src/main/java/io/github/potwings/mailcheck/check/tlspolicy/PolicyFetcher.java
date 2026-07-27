package io.github.potwings.mailcheck.check.tlspolicy;

/**
 * Fetches the MTA-STS policy file over HTTPS. Abstracted so the check stays
 * unit-testable without network access (same rule as DnsQueryService).
 */
public interface PolicyFetcher {

    /** Returns the body of {@code https://mta-sts.<domain>/.well-known/mta-sts.txt} (HTTP 200 only). */
    String fetch(String domain) throws Exception;
}
