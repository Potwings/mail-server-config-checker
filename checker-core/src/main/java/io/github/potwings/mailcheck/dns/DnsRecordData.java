package io.github.potwings.mailcheck.dns;

/**
 * @param value normalized rdata: TXT = concatenated character-strings, MX = "pref host",
 *              A/AAAA = address literal, NS/CNAME/PTR = target hostname without trailing dot
 * @param ttl   remaining TTL as reported by the answering resolver (seconds)
 */
public record DnsRecordData(String value, long ttl) {
}
