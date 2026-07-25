package io.github.potwings.mailcheck.engine;

import io.github.potwings.mailcheck.dns.DnsAnswer;
import io.github.potwings.mailcheck.dns.DnsQueryService;
import io.github.potwings.mailcheck.dns.RecordType;

import java.util.Comparator;
import java.util.List;
import java.util.Optional;

/**
 * Decides which IPs the PTR/RBL checks target: user-supplied IPs win; otherwise
 * every A record of the best-priority MX host. Stage-1 limitation (checking the
 * inbound MX IPs, not the actual outbound IPs) is surfaced via the source label.
 */
public class TargetIpResolver {

    public record TargetIps(List<String> ips, String source, boolean userProvided) {
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
                return Optional.of(new TargetIps(cleaned, "사용자 입력", true));
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
        if (a.failed() || !a.hasRecords()) {
            return Optional.empty();
        }
        List<String> ips = a.values().stream().distinct().toList();
        return Optional.of(new TargetIps(ips, "MX(" + bestHost.get() + ")의 A 레코드에서 도출", false));
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
