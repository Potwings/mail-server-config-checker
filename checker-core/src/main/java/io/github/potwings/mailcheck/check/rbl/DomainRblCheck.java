package io.github.potwings.mailcheck.check.rbl;

import io.github.potwings.mailcheck.api.Check;
import io.github.potwings.mailcheck.api.CheckContext;
import io.github.potwings.mailcheck.api.CheckResult;
import io.github.potwings.mailcheck.api.CheckStatus;
import io.github.potwings.mailcheck.dns.DnsQueryService;
import io.github.potwings.mailcheck.dns.RecordType;

import java.util.List;

/**
 * Domain-based RBL check — is the domain itself blacklisted (not its IPs)?
 * Any LISTED → FAIL; query errors → WARN (never silently treated as clean).
 */
public class DomainRblCheck implements Check {

    private final DnsQueryService dns;
    private final List<DomainRblProvider> providers;

    public DomainRblCheck(DnsQueryService dns, List<DomainRblProvider> providers) {
        this.dns = dns;
        this.providers = List.copyOf(providers);
    }

    @Override
    public String id() {
        return "domain-rbl";
    }

    @Override
    public String title() {
        return "도메인 RBL 등재 여부 (DBL)";
    }

    @Override
    public CheckResult run(CheckContext ctx) {
        CheckResult.Builder b = CheckResult.builder(id(), title());
        b.evidence("검사 대상 도메인: " + ctx.domain());

        providers.stream().filter(p -> !p.enabled())
                .forEach(p -> b.evidence(p.name() + ": 건너뜀 — " + p.disabledReason()));
        List<DomainRblProvider> active = providers.stream().filter(DomainRblProvider::enabled).toList();

        boolean listed = false;
        boolean abusedLegit = false;
        int checkedCount = 0;
        for (DomainRblProvider p : active) {
            RblVerdict v = p.interpret(dns.query(p.queryName(ctx.domain()), RecordType.A));
            switch (v.type()) {
                case LISTED -> {
                    listed = true;
                    checkedCount++;
                    abusedLegit |= v.listings().stream().anyMatch(l -> l.contains("악용된 정상 도메인"));
                    b.evidence(p.name() + ": 등재됨 — " + String.join(", ", v.listings()));
                }
                case NOT_LISTED -> {
                    checkedCount++;
                    b.evidence(p.name() + ": 미등재");
                }
                case ERROR -> b.atLeast(CheckStatus.WARN)
                        .evidence(p.name() + ": 확인 불가 — " + v.detail());
                case SKIPPED -> b.evidence(p.name() + ": 건너뜀 — " + v.detail());
            }
        }

        if (listed) {
            b.status(CheckStatus.FAIL)
                    .guidance("https://check.spamhaus.org 에서 도메인 등재 사유를 확인하고 해제(delisting)를 요청하세요");
            if (abusedLegit) {
                b.guidance("'악용된 정상 도메인' 등재는 사이트 해킹/오픈 리다이렉터 악용이 원인일 수 있으니 웹 서버 취약점 점검 후 해제를 요청하세요");
            }
        } else if (checkedCount == 0) {
            b.atLeast(CheckStatus.SKIP).evidence("실제 조회에 성공한 도메인 RBL이 없음");
        }
        return b.build();
    }
}
