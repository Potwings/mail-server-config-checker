package io.github.potwings.mailcheck.check.spf;

import io.github.potwings.mailcheck.api.Check;
import io.github.potwings.mailcheck.api.CheckContext;
import io.github.potwings.mailcheck.api.CheckResult;
import io.github.potwings.mailcheck.api.CheckStatus;
import io.github.potwings.mailcheck.check.spf.SpfRecordParser.ParseResult;
import io.github.potwings.mailcheck.check.spf.SpfRecordParser.SpfTerm;
import io.github.potwings.mailcheck.dns.DnsAnswer;
import io.github.potwings.mailcheck.dns.DnsQueryService;
import io.github.potwings.mailcheck.dns.RecordType;

import java.util.List;
import java.util.Locale;

/**
 * SPF validation per RFC 7208: record-level lint always, plus check_host()
 * evaluation of the user-declared sending IPs when they were entered. MX-derived
 * IPs are inbound addresses, so they are never evaluated against SPF.
 */
public class SpfCheck implements Check {

    private final DnsQueryService dns;
    private final SpfRecordParser parser = new SpfRecordParser();
    private final SpfLookupCounter counter;
    private final SpfEvaluator evaluator;

    public SpfCheck(DnsQueryService dns) {
        this.dns = dns;
        this.counter = new SpfLookupCounter(dns);
        this.evaluator = new SpfEvaluator(dns);
    }

    @Override
    public String id() {
        return "spf";
    }

    @Override
    public String title() {
        return "SPF";
    }

    @Override
    public CheckResult run(CheckContext ctx) {
        CheckResult.Builder b = CheckResult.builder(id(), title());
        String domain = ctx.domain();

        DnsAnswer ans = dns.query(domain, RecordType.TXT);
        if (ans.failed()) {
            return b.status(CheckStatus.ERROR)
                    .evidence("TXT 조회 실패 (" + ans.rcode() + ")")
                    .build();
        }
        if (ans.isNxDomain()) {
            return b.status(CheckStatus.FAIL)
                    .evidence("도메인이 존재하지 않음 (NXDOMAIN)")
                    .build();
        }

        List<String> spfRecords = ans.values().stream().filter(SpfRecordParser::isSpfRecord).toList();
        if (spfRecords.isEmpty()) {
            return b.status(CheckStatus.FAIL)
                    .evidence("SPF(v=spf1) TXT 레코드가 없음")
                    .guidance("도메인에 \"v=spf1 <허용 IP/include> ~all\" 형태의 TXT 레코드를 추가하세요")
                    .build();
        }
        if (spfRecords.size() > 1) {
            b.status(CheckStatus.FAIL)
                    .evidence("SPF 레코드가 " + spfRecords.size() + "개 존재 — RFC 7208 §4.5 위반, 수신 서버는 permerror 처리")
                    .guidance("SPF 레코드를 하나로 병합하세요 (여러 레코드는 합집합이 아니라 오류로 처리됩니다)");
            spfRecords.forEach(r -> b.evidence("레코드: " + r));
            return b.build();
        }

        String record = spfRecords.get(0);
        b.evidence("레코드: " + record);

        ParseResult parsed = parser.parse(record);
        parsed.warnings().forEach(w -> b.atLeast(CheckStatus.WARN).evidence("구문 경고: " + w));
        if (!parsed.errors().isEmpty()) {
            parsed.errors().forEach(e -> b.evidence("구문 오류: " + e));
            return b.status(CheckStatus.FAIL)
                    .guidance("구문 오류는 permerror로 이어져 SPF 전체가 무효화됩니다 — 레코드를 수정하세요")
                    .build();
        }

        SpfLookupCounter.CountResult count = counter.count(domain, parsed.terms());
        b.evidence("DNS lookup: " + count.lookups() + "/" + SpfLookupCounter.MAX_LOOKUPS
                + ", void lookup: " + count.voidLookups() + "/" + SpfLookupCounter.MAX_VOID_LOOKUPS);
        count.notes().forEach(b::evidence);
        if (count.fatal() != null) {
            b.status(CheckStatus.FAIL).evidence(count.fatal())
                    .guidance("include 체인을 정리해 DNS lookup 수를 10 이하로 줄이세요 (ip4/ip6 직접 명시 또는 SPF flattening)");
        }

        evaluateTerminalPolicy(parsed.terms(), b);

        if (count.fatal() == null) {
            evaluateSenderIps(ctx, parsed.terms(), b);
        }
        return b.build();
    }

    /** check_host() per user-supplied sending IP; worst-of aggregation, guidance once. */
    private void evaluateSenderIps(CheckContext ctx, List<SpfTerm> terms, CheckResult.Builder b) {
        if (!ctx.hasTargetIps() || !ctx.ipsUserProvided()) {
            b.evidence("※ 발신 서버 IP를 입력하면 해당 IP가 SPF에 허용되는지(check_host)까지 평가합니다");
            return;
        }

        List<String> ips = ctx.targetIps();
        boolean anyNotAuthorized = false;
        boolean anyPermerror = false;
        for (String ip : ips) {
            // Prefix evidence with the IP only when there are several; the label then
            // drops the IP so it is not printed twice on the same line.
            String tag = ips.size() > 1 ? "[" + ip + "] " : "";
            String label = tag.isEmpty() ? "발신 IP " + ip + " 평가: " : "발신 IP 평가: ";
            SpfEvaluator.Evaluation ev = evaluator.evaluate(ip, ctx.domain(), terms);
            ev.notes().forEach(n -> b.evidence(tag + n));
            String matched = ev.matched() == null ? "" : " (매칭: " + ev.matched() + ")";
            switch (ev.verdict()) {
                case PASS -> b.evidence(tag + label + "pass" + matched);
                case FAIL, SOFTFAIL, NEUTRAL -> {
                    anyNotAuthorized = true;
                    b.atLeast(CheckStatus.FAIL).evidence(tag + label
                            + ev.verdict().name().toLowerCase(Locale.ROOT)
                            + " — 이 IP는 SPF 허용 목록에 포함되지 않음" + matched);
                }
                case PERMERROR -> {
                    anyPermerror = true;
                    b.atLeast(CheckStatus.FAIL).evidence(tag + label + "permerror" + matched);
                }
                case TEMPERROR -> b.atLeast(CheckStatus.ERROR)
                        .evidence(tag + label + "temperror — DNS 조회 실패" + matched);
            }
        }
        if (anyNotAuthorized) {
            b.guidance("발신 서버 IP가 SPF에 허용되어 있지 않습니다 — 레코드에 \"ip4:<IP>\"(IPv6는 ip6:)를 추가하거나 해당 IP를 포함하는 include를 사용하세요");
        }
        if (anyPermerror) {
            b.guidance("permerror는 수신 서버가 SPF 전체를 무효 처리하는 상태입니다 — evidence의 원인을 수정하세요");
        }
    }

    private void evaluateTerminalPolicy(List<SpfTerm> terms, CheckResult.Builder b) {
        SpfTerm all = null;
        int allIndex = -1;
        int lastMechanismIndex = -1;
        for (int i = 0; i < terms.size(); i++) {
            SpfTerm t = terms.get(i);
            if (!t.modifier()) {
                lastMechanismIndex = i;
                if (t.name().equals("all")) {
                    all = t;
                    allIndex = i;
                }
            }
        }

        if (all == null) {
            boolean hasRedirect = terms.stream().anyMatch(t -> t.modifier() && t.name().equals("redirect"));
            if (hasRedirect) {
                b.evidence("종단 정책: redirect 대상 도메인의 정책을 따름");
            } else {
                b.atLeast(CheckStatus.WARN)
                        .evidence("종단 all 메커니즘이 없음 — 미매칭 발신이 neutral 처리됨")
                        .guidance("레코드 끝에 ~all(softfail) 또는 -all(hardfail)을 추가하세요");
            }
            return;
        }

        if (allIndex < lastMechanismIndex) {
            b.atLeast(CheckStatus.WARN)
                    .evidence("all 이후에 메커니즘이 있음 — all 뒤의 항목은 평가되지 않음");
        }

        switch (all.qualifier()) {
            case '+' -> b.atLeast(CheckStatus.WARN)
                    .evidence("종단 정책: +all — 전 세계 모든 IP의 발신을 허용하는 과허용 설정")
                    .guidance("+all은 SPF를 무력화합니다. ~all 또는 -all로 변경하세요");
            case '?' -> b.atLeast(CheckStatus.WARN)
                    .evidence("종단 정책: ?all(neutral) — 사실상 판정 포기")
                    .guidance("~all 또는 -all로 강화하는 것을 권장합니다");
            case '~' -> b.evidence("종단 정책: ~all (softfail)");
            case '-' -> b.evidence("종단 정책: -all (hardfail)");
            default -> {
            }
        }
    }
}
