package io.github.potwings.mailcheck.dns;

import java.util.List;

public record DnsAnswer(DnsRcode rcode, List<DnsRecordData> records) {

    public static DnsAnswer of(DnsRcode rcode) {
        return new DnsAnswer(rcode, List.of());
    }

    public boolean isNxDomain() {
        return rcode == DnsRcode.NXDOMAIN;
    }

    /** Query itself failed (timeout, servfail, ...) — distinct from "no records". */
    public boolean failed() {
        return rcode == DnsRcode.TIMEOUT || rcode == DnsRcode.SERVFAIL || rcode == DnsRcode.ERROR;
    }

    public boolean hasRecords() {
        return !records.isEmpty();
    }

    public List<String> values() {
        return records.stream().map(DnsRecordData::value).toList();
    }

    public long minTtl() {
        return records.stream().mapToLong(DnsRecordData::ttl).min().orElse(0);
    }
}
