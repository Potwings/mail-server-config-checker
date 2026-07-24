package io.github.potwings.mailcheck.engine;

import io.github.potwings.mailcheck.dns.DnsAnswer;
import io.github.potwings.mailcheck.dns.DnsQueryService;
import io.github.potwings.mailcheck.dns.RecordType;

import java.util.Comparator;
import java.util.Optional;

/**
 * Decides which IP the PTR/RBL checks target: user-supplied IP wins; otherwise
 * the A record of the best-priority MX host. Stage-1 limitation (checking the
 * inbound MX IP, not the actual outbound IP) is surfaced via the source label.
 */
public class TargetIpResolver {

    public record TargetIp(String ip, String source) {
    }

    private final DnsQueryService dns;

    public TargetIpResolver(DnsQueryService dns) {
        this.dns = dns;
    }

    public Optional<TargetIp> resolve(String domain, String ipOverride) {
        if (ipOverride != null && !ipOverride.isBlank()) {
            return Optional.of(new TargetIp(ipOverride.trim(), "사용자 입력"));
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
        return Optional.of(new TargetIp(a.values().get(0), "MX(" + bestHost.get() + ")의 A 레코드에서 도출"));
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
