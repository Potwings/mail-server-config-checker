package io.github.potwings.mailcheck.check.tlspolicy;

import io.github.potwings.mailcheck.api.Check;
import io.github.potwings.mailcheck.api.CheckContext;
import io.github.potwings.mailcheck.api.CheckResult;
import io.github.potwings.mailcheck.api.CheckStatus;
import io.github.potwings.mailcheck.dns.DnsAnswer;
import io.github.potwings.mailcheck.dns.DnsQueryService;
import io.github.potwings.mailcheck.dns.RecordType;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * MTA-STS (RFC 8461) + TLS-RPT (RFC 8460) in one card: TXT discovery, HTTPS
 * policy fetch/parse, policy-vs-MX comparison, and report record sanity.
 * Both are recommendations, so absence is WARN (not FAIL) — consistent with
 * the missing-rua handling in the DMARC check.
 */
public class TlsPolicyCheck implements Check {

    private final DnsQueryService dns;
    private final PolicyFetcher fetcher;

    public TlsPolicyCheck(DnsQueryService dns, PolicyFetcher fetcher) {
        this.dns = dns;
        this.fetcher = fetcher;
    }

    @Override
    public String id() {
        return "tls-policy";
    }

    @Override
    public String title() {
        return "TLS 정책 (MTA-STS / TLS-RPT)";
    }

    @Override
    public CheckResult run(CheckContext ctx) {
        CheckResult.Builder b = CheckResult.builder(id(), title());
        checkMtaSts(ctx.domain(), b);
        checkTlsRpt(ctx.domain(), b);
        return b.build();
    }

    private void checkMtaSts(String domain, CheckResult.Builder b) {
        String qname = "_mta-sts." + domain;
        DnsAnswer ans = dns.query(qname, RecordType.TXT);
        if (ans.failed()) {
            b.atLeast(CheckStatus.ERROR).evidence(qname + " TXT 조회 실패 (" + ans.rcode() + ")");
            return;
        }
        List<String> records = ans.values().stream()
                .filter(v -> v.trim().toLowerCase(Locale.ROOT).startsWith("v=stsv1"))
                .toList();
        if (records.isEmpty()) {
            b.atLeast(CheckStatus.WARN)
                    .evidence("MTA-STS 미설정 (" + qname + " TXT 없음) — 수신 구간 TLS가 강제되지 않음")
                    .guidance("MTA-STS 도입을 권장합니다: " + qname + " TXT(v=STSv1; id=...)와 "
                            + "https://mta-sts." + domain + "/.well-known/mta-sts.txt 정책 파일을 게시하세요 "
                            + "(Gmail 등 주요 수신자가 적용 중)");
            return;
        }
        if (records.size() > 1) {
            b.atLeast(CheckStatus.WARN)
                    .evidence("MTA-STS TXT 레코드가 " + records.size() + "개 — 발신자는 없는 것으로 취급 (RFC 8461 §3.1)")
                    .guidance("MTA-STS TXT 레코드를 하나만 남기세요");
            return;
        }
        String record = records.get(0);
        b.evidence("MTA-STS 레코드: " + record);
        if (!record.toLowerCase(Locale.ROOT).contains("id=")) {
            b.atLeast(CheckStatus.WARN).evidence("MTA-STS TXT에 id= 태그가 없음 — 정책 갱신을 발신자가 감지하지 못함");
        }

        String body;
        try {
            body = fetcher.fetch(domain);
        } catch (Exception e) {
            b.atLeast(CheckStatus.FAIL)
                    .evidence("정책 파일(https://mta-sts." + domain + "/.well-known/mta-sts.txt)을 가져올 수 없음: "
                            + e.getMessage())
                    .guidance("TXT만 있고 정책 파일이 없으면 MTA-STS는 동작하지 않습니다 — "
                            + "mta-sts." + domain + " HTTPS 서버에 정책 파일을 게시하세요");
            return;
        }

        Policy policy = Policy.parse(body);
        if (!"STSv1".equalsIgnoreCase(policy.version)) {
            b.atLeast(CheckStatus.FAIL).evidence("정책 파일 version이 STSv1이 아님: " + policy.version);
            return;
        }
        String mode = policy.mode == null ? "" : policy.mode.toLowerCase(Locale.ROOT);
        switch (mode) {
            case "enforce" -> b.evidence("정책 mode=enforce — TLS 미지원/인증 실패 시 배송 차단 (권장 최종 상태)");
            case "testing" -> b.atLeast(CheckStatus.WARN)
                    .evidence("정책 mode=testing — 위반을 리포트만 하고 배송은 차단하지 않음")
                    .guidance("TLS-RPT 리포트로 문제가 없음을 확인한 뒤 mode=enforce로 전환하세요");
            case "none" -> b.atLeast(CheckStatus.WARN).evidence("정책 mode=none — MTA-STS 비활성 선언 상태");
            default -> {
                b.atLeast(CheckStatus.FAIL).evidence("정책 mode 값이 유효하지 않음: " + policy.mode);
                return;
            }
        }
        if (policy.maxAge != null) {
            b.evidence("정책 max_age=" + policy.maxAge + "초");
        }

        compareMx(domain, policy, mode, b);
    }

    /** In enforce mode an MX outside the policy's mx patterns means senders refuse delivery to it. */
    private void compareMx(String domain, Policy policy, String mode, CheckResult.Builder b) {
        if (policy.mxPatterns.isEmpty()) {
            b.atLeast(CheckStatus.WARN).evidence("정책 파일에 mx 항목이 없음");
            return;
        }
        DnsAnswer mx = dns.query(domain, RecordType.MX);
        if (mx.failed() || !mx.hasRecords()) {
            b.evidence("MX를 확인할 수 없어 정책 mx 대조 생략");
            return;
        }
        List<String> unmatched = new ArrayList<>();
        for (String v : mx.values()) {
            String[] parts = v.trim().split("\\s+", 2);
            if (parts.length != 2 || parts[1].equals(".")) {
                continue;
            }
            String host = parts[1].toLowerCase(Locale.ROOT);
            if (policy.mxPatterns.stream().noneMatch(p -> matchesMxPattern(host, p))) {
                unmatched.add(host);
            }
        }
        if (unmatched.isEmpty()) {
            b.evidence("모든 MX가 정책 mx 목록과 일치");
            return;
        }
        boolean enforce = mode.equals("enforce");
        b.atLeast(enforce ? CheckStatus.FAIL : CheckStatus.WARN)
                .evidence("정책 mx 목록과 불일치하는 MX: " + String.join(", ", unmatched)
                        + (enforce ? " — enforce 모드에서 발신자가 이 MX로의 배송을 거부함" : ""))
                .guidance("정책 파일의 mx 항목과 실제 MX 레코드를 일치시키세요 (MX 변경 시 정책 파일과 id= 갱신 필요)");
    }

    /** RFC 8461 §4.1 — "*.example.com" matches exactly one additional leftmost label. */
    static boolean matchesMxPattern(String host, String pattern) {
        String p = pattern.toLowerCase(Locale.ROOT);
        String h = host.toLowerCase(Locale.ROOT);
        if (p.startsWith("*.")) {
            String suffix = p.substring(1); // ".example.com"
            if (!h.endsWith(suffix)) {
                return false;
            }
            String label = h.substring(0, h.length() - suffix.length());
            return !label.isEmpty() && !label.contains(".");
        }
        return h.equals(p);
    }

    private void checkTlsRpt(String domain, CheckResult.Builder b) {
        String qname = "_smtp._tls." + domain;
        DnsAnswer ans = dns.query(qname, RecordType.TXT);
        if (ans.failed()) {
            b.atLeast(CheckStatus.ERROR).evidence(qname + " TXT 조회 실패 (" + ans.rcode() + ")");
            return;
        }
        List<String> records = ans.values().stream()
                .filter(v -> v.trim().toLowerCase(Locale.ROOT).startsWith("v=tlsrptv1"))
                .toList();
        if (records.isEmpty()) {
            b.atLeast(CheckStatus.WARN)
                    .evidence("TLS-RPT 미설정 (" + qname + " TXT 없음) — TLS 협상 실패를 알 방법이 없음")
                    .guidance(qname + " 에 \"v=TLSRPTv1; rua=mailto:...\" TXT를 추가하면 "
                            + "수신자가 TLS 실패 리포트를 보내줍니다 (MTA-STS 운영 시 사실상 필수)");
            return;
        }
        if (records.size() > 1) {
            b.atLeast(CheckStatus.WARN)
                    .evidence("TLS-RPT TXT 레코드가 " + records.size() + "개 — 수신자는 무시함 (RFC 8460 §3)");
            return;
        }
        String record = records.get(0);
        b.evidence("TLS-RPT 레코드: " + record);
        if (!record.toLowerCase(Locale.ROOT).contains("rua=")) {
            b.atLeast(CheckStatus.WARN).evidence("TLS-RPT에 rua= 가 없음 — 리포트 수신처가 지정되지 않음");
        }
    }

    private record Policy(String version, String mode, String maxAge, List<String> mxPatterns) {

        static Policy parse(String body) {
            String version = null;
            String mode = null;
            String maxAge = null;
            List<String> mx = new ArrayList<>();
            for (String line : body.split("\r?\n")) {
                int colon = line.indexOf(':');
                if (colon <= 0) {
                    continue;
                }
                String key = line.substring(0, colon).trim().toLowerCase(Locale.ROOT);
                String value = line.substring(colon + 1).trim();
                switch (key) {
                    case "version" -> version = value;
                    case "mode" -> mode = value;
                    case "max_age" -> maxAge = value;
                    case "mx" -> mx.add(value);
                    default -> {
                    }
                }
            }
            return new Policy(version, mode, maxAge, List.copyOf(mx));
        }
    }
}
