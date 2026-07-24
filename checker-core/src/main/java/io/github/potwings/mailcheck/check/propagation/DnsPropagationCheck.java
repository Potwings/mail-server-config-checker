package io.github.potwings.mailcheck.check.propagation;

import io.github.potwings.mailcheck.api.Check;
import io.github.potwings.mailcheck.api.CheckContext;
import io.github.potwings.mailcheck.api.CheckResult;
import io.github.potwings.mailcheck.api.CheckStatus;
import io.github.potwings.mailcheck.check.dmarc.OrgDomainResolver;
import io.github.potwings.mailcheck.check.spf.SpfRecordParser;
import io.github.potwings.mailcheck.dns.DnsAnswer;
import io.github.potwings.mailcheck.dns.DnsQueryService;
import io.github.potwings.mailcheck.dns.RecordType;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.function.Predicate;

/**
 * Compares the authoritative answer (baseline, queried directly at the domain's NS)
 * with what public/ISP resolvers currently serve, to distinguish "record is wrong"
 * from "record is still propagating through caches".
 */
public class DnsPropagationCheck implements Check {

    private final DnsQueryService dns;
    private final List<ResolverEndpoint> resolvers;
    private final OrgDomainResolver orgResolver;

    public DnsPropagationCheck(DnsQueryService dns, List<ResolverEndpoint> resolvers, OrgDomainResolver orgResolver) {
        this.dns = dns;
        this.resolvers = List.copyOf(resolvers);
        this.orgResolver = orgResolver;
    }

    @Override
    public String id() {
        return "propagation";
    }

    @Override
    public String title() {
        return "DNS 전파 (다중 리졸버)";
    }

    private record Probe(String label, String qname, RecordType type, Predicate<String> filter) {
    }

    private record ResolverResult(ResolverEndpoint resolver, boolean answered, boolean matched, long ttl) {
    }

    @Override
    public CheckResult run(CheckContext ctx) {
        CheckResult.Builder b = CheckResult.builder(id(), title());
        String domain = ctx.domain();

        String authIp = findAuthoritativeIp(domain, b);
        if (authIp == null) {
            return b.status(CheckStatus.ERROR)
                    .evidence("권한 네임서버(NS)를 확인할 수 없어 기준값 조회 불가")
                    .build();
        }

        List<Probe> probes = List.of(
                new Probe("A", domain, RecordType.A, v -> true),
                new Probe("MX", domain, RecordType.MX, v -> true),
                new Probe("SPF", domain, RecordType.TXT, SpfRecordParser::isSpfRecord),
                new Probe("DMARC", "_dmarc." + domain, RecordType.TXT,
                        v -> v.trim().toLowerCase(Locale.ROOT).startsWith("v=dmarc1")));

        boolean anyMismatch = false;
        for (Probe probe : probes) {
            List<String> baseline = normalize(dns.queryVia(authIp, probe.qname(), probe.type()), probe.filter());

            List<CompletableFuture<Map.Entry<ResolverEndpoint, DnsAnswer>>> futures = resolvers.stream()
                    .map(r -> CompletableFuture.supplyAsync(() ->
                            Map.entry(r, dns.queryVia(r.ip(), probe.qname(), probe.type()))))
                    .toList();

            List<ResolverResult> results = new ArrayList<>();
            for (CompletableFuture<Map.Entry<ResolverEndpoint, DnsAnswer>> f : futures) {
                Map.Entry<ResolverEndpoint, DnsAnswer> entry = f.join();
                DnsAnswer answer = entry.getValue();
                if (answer.failed()) {
                    results.add(new ResolverResult(entry.getKey(), false, false, 0));
                } else {
                    List<String> values = normalize(answer, probe.filter());
                    results.add(new ResolverResult(entry.getKey(), true, values.equals(baseline), answer.minTtl()));
                }
            }

            long answered = results.stream().filter(ResolverResult::answered).count();
            long matched = results.stream().filter(ResolverResult::matched).count();
            List<String> mismatchNames = results.stream()
                    .filter(r -> r.answered() && !r.matched())
                    .map(r -> r.resolver().name())
                    .toList();
            List<String> silentNames = results.stream()
                    .filter(r -> !r.answered())
                    .map(r -> r.resolver().name())
                    .toList();

            StringBuilder line = new StringBuilder(probe.label() + ": " + matched + "/" + answered + " 리졸버 일치");
            if (!mismatchNames.isEmpty()) {
                anyMismatch = true;
                long maxTtl = results.stream()
                        .filter(r -> r.answered() && !r.matched())
                        .mapToLong(ResolverResult::ttl)
                        .max().orElse(0);
                line.append(" — 불일치: ").append(String.join(", ", mismatchNames));
                if (maxTtl > 0) {
                    line.append(" (캐시 잔여 TTL 최대 ").append(maxTtl).append("초 → 그 후 갱신 예상)");
                }
            }
            if (!silentNames.isEmpty()) {
                line.append(" / 응답 없음: ").append(String.join(", ", silentNames));
            }
            b.evidence(line.toString());
        }

        if (anyMismatch) {
            b.atLeast(CheckStatus.WARN)
                    .guidance("레코드를 최근 변경했다면 전파 진행 중일 수 있습니다. 표시된 TTL 경과 후 재검사하세요")
                    .guidance("참고: Quad9는 차단 대상 도메인에 변조 응답을 줄 수 있어 단독 불일치는 오탐일 수 있습니다");
        } else {
            b.evidence("권한 NS 기준값과 모든 응답 리졸버가 일치 — 전파 완료 상태");
        }
        return b.build();
    }

    /** Finds one authoritative nameserver IP: NS of the domain, falling back to the org domain. */
    private String findAuthoritativeIp(String domain, CheckResult.Builder b) {
        DnsAnswer ns = dns.query(domain, RecordType.NS);
        if (ns.failed() || !ns.hasRecords()) {
            String org = orgResolver.organizationalDomain(domain);
            if (!org.equalsIgnoreCase(domain)) {
                ns = dns.query(org, RecordType.NS);
            }
        }
        if (ns.failed() || !ns.hasRecords()) {
            return null;
        }
        String nsHost = ns.values().get(0);
        DnsAnswer a = dns.query(nsHost, RecordType.A);
        if (a.failed() || !a.hasRecords()) {
            return null;
        }
        String ip = a.values().get(0);
        b.evidence("기준 권한 NS: " + nsHost + " (" + ip + ")");
        return ip;
    }

    private static List<String> normalize(DnsAnswer answer, Predicate<String> filter) {
        return answer.values().stream()
                .map(v -> v.trim().toLowerCase(Locale.ROOT))
                .filter(filter)
                .sorted()
                .toList();
    }
}
