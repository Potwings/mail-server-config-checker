package io.github.potwings.mailcheck.dns;

/**
 * Thin DNS facade so checks never touch dnsjava directly — keeps checks unit-testable
 * and lets the caller choose the resolver per query (propagation checks, RBL via DQS).
 */
public interface DnsQueryService {

    /** Query via the system default resolver. For PTR, {@code name} is the IP literal. */
    DnsAnswer query(String name, RecordType type);

    /** Query via a specific resolver IP (public resolvers, authoritative NS, ...). */
    DnsAnswer queryVia(String resolverIp, String name, RecordType type);
}
