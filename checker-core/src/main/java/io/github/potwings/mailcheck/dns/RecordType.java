package io.github.potwings.mailcheck.dns;

public enum RecordType {
    A,
    AAAA,
    TXT,
    MX,
    NS,
    CNAME,
    /** For PTR the query name is the raw IP; the service builds the in-addr.arpa name. */
    PTR
}
