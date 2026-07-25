package io.github.potwings.mailcheck.check.rbl;

import io.github.potwings.mailcheck.api.Check;
import io.github.potwings.mailcheck.api.CheckContext;
import io.github.potwings.mailcheck.api.CheckResult;
import io.github.potwings.mailcheck.api.CheckStatus;
import io.github.potwings.mailcheck.dns.DnsQueryService;
import io.github.potwings.mailcheck.dns.RecordType;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * Queries all configured RBL zones for every target IP in parallel
 * (provider × IP fan-out). Any LISTED → FAIL; query errors → WARN
 * (never silently treated as clean).
 */
public class RblCheck implements Check {

    private final DnsQueryService dns;
    private final List<RblProvider> providers;

    public RblCheck(DnsQueryService dns, List<RblProvider> providers) {
        this.dns = dns;
        this.providers = List.copyOf(providers);
    }

    @Override
    public String id() {
        return "rbl";
    }

    @Override
    public String title() {
        return "RBL 등재 여부";
    }

    @Override
    public CheckResult run(CheckContext ctx) {
        CheckResult.Builder b = CheckResult.builder(id(), title());

        if (!ctx.hasTargetIps()) {
            return b.status(CheckStatus.SKIP)
                    .evidence("검사 대상 IP를 확인할 수 없어 건너뜀 (MX 미존재 또는 해석 실패)")
                    .guidance("검사할 발신 서버 IP를 직접 입력하면 RBL 검사가 수행됩니다")
                    .build();
        }
        List<String> ips = ctx.targetIps();
        List<String> v4 = ips.stream().filter(ip -> !ip.contains(":")).toList();
        if (v4.isEmpty()) {
            return b.status(CheckStatus.SKIP)
                    .evidence("IPv6 주소 — 1단계에서는 IPv4 RBL만 지원")
                    .build();
        }
        b.evidence("검사 대상 IP: " + String.join(", ", ips) + " (" + ctx.targetIpSource() + ")");
        ips.stream().filter(ip -> ip.contains(":"))
                .forEach(ip -> b.evidence("[" + ip + "] IPv6 주소 — RBL 검사에서 제외 (1단계에서는 IPv4만 지원)"));

        // Disabled providers are reported once, not per IP.
        providers.stream().filter(p -> !p.enabled())
                .forEach(p -> b.evidence(p.name() + ": 건너뜀 — " + p.disabledReason()));
        List<RblProvider> active = providers.stream().filter(RblProvider::enabled).toList();

        // Prefix evidence with the IP only when there are several, so single-IP output stays clean.
        boolean multi = v4.size() > 1;

        record Outcome(String ip, RblProvider provider, RblVerdict verdict) {
        }

        List<CompletableFuture<Outcome>> futures = new ArrayList<>();
        for (String ip : v4) {
            String reversed = reverseOctets(ip);
            for (RblProvider p : active) {
                futures.add(CompletableFuture.supplyAsync(
                        () -> new Outcome(ip, p, p.interpret(dns.query(p.queryName(reversed), RecordType.A)))));
            }
        }

        int listedCount = 0;
        int checkedCount = 0;
        for (CompletableFuture<Outcome> f : futures) {
            Outcome o = f.join();
            String tag = multi ? "[" + o.ip() + "] " : "";
            switch (o.verdict().type()) {
                case LISTED -> {
                    listedCount++;
                    checkedCount++;
                    b.evidence(tag + o.provider().name() + ": 등재됨 — " + String.join(", ", o.verdict().listings()));
                }
                case NOT_LISTED -> {
                    checkedCount++;
                    b.evidence(tag + o.provider().name() + ": 미등재");
                }
                case ERROR -> b.atLeast(CheckStatus.WARN)
                        .evidence(tag + o.provider().name() + ": 확인 불가 — " + o.verdict().detail());
                case SKIPPED -> b.evidence(tag + o.provider().name() + ": 건너뜀 — " + o.verdict().detail());
            }
        }

        if (listedCount > 0) {
            b.status(CheckStatus.FAIL)
                    .guidance("등재 사유를 해소한 뒤 각 RBL의 해제(delisting) 절차를 진행하세요. PBL 등재는 발신 IP가 동적 대역이라는 뜻으로, 고정 IP/정식 발신 경로 사용이 근본 해결책입니다");
        } else if (checkedCount == 0) {
            b.atLeast(CheckStatus.SKIP).evidence("실제 조회에 성공한 RBL이 없음");
        }
        return b.build();
    }

    static String reverseOctets(String ipv4) {
        String[] o = ipv4.split("\\.");
        return o[3] + "." + o[2] + "." + o[1] + "." + o[0];
    }
}
