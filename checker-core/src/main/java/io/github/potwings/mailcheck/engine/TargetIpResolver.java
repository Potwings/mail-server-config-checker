package io.github.potwings.mailcheck.engine;

import io.github.potwings.mailcheck.dns.DnsAnswer;
import io.github.potwings.mailcheck.dns.DnsQueryService;
import io.github.potwings.mailcheck.dns.RecordType;
import io.github.potwings.mailcheck.net.IpRanges;

import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * Decides which IPs the PTR/RBL checks target: user-supplied IPs win; otherwise
 * every A/AAAA record of the best-priority MX host. Stage-1 limitation (checking
 * the inbound MX IPs, not the actual outbound IPs) is surfaced via the source label.
 */
public class TargetIpResolver {

    public record TargetIps(List<String> ips, String source) {
    }

    private final DnsQueryService dns;

    public TargetIpResolver(DnsQueryService dns) {
        this.dns = dns;
    }

    public Optional<TargetIps> resolve(String domain, List<String> ipOverrides) {
        if (ipOverrides != null) {
            List<String> cleaned = ipOverrides.stream()
                    .filter(ip -> ip != null && !ip.isBlank())
                    .map(String::trim)
                    .distinct()
                    .toList();
            if (!cleaned.isEmpty()) {
                return Optional.of(new TargetIps(cleaned, "사용자 입력"));
            }
        }

        DnsAnswer mx = dns.query(domain, RecordType.MX);
        if (mx.failed() || !mx.hasRecords()) {
            return Optional.empty();
        }

        Optional<String> bestHost = mx.values().stream()
                .map(TargetIpResolver::parseMx)
                .filter(e -> e != null && !e.host().equals("."))
                .min(Comparator.comparingInt(MxEntry::pref))
                .map(MxEntry::host);
        if (bestHost.isEmpty()) {
            return Optional.empty();
        }

        DnsAnswer a = dns.query(bestHost.get(), RecordType.A);
        DnsAnswer aaaa = dns.query(bestHost.get(), RecordType.AAAA);
        // Private/reserved MX IPs are useless (and misleading) as PTR/RBL targets — drop them.
        List<String> ips = Stream.concat(
                        a.failed() ? Stream.<String>empty() : a.values().stream(),
                        aaaa.failed() ? Stream.<String>empty() : aaaa.values().stream())
                .distinct()
                .filter(ip -> IpRanges.nonRoutableReason(ip) == null)
                .toList();
        if (ips.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(new TargetIps(ips, "MX(" + bestHost.get() + ")의 A/AAAA 레코드에서 도출"));
    }

    private record MxEntry(int pref, String host) {
    }

    private static MxEntry parseMx(String value) {
        String[] parts = value.trim().split("\\s+", 2);
        if (parts.length != 2) {
            return null;
        }
        try {
            return new MxEntry(Integer.parseInt(parts[0]), parts[1]);
        } catch (NumberFormatException e) {
            return null;
        }
    }
}
