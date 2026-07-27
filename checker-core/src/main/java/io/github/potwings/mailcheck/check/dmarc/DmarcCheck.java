package io.github.potwings.mailcheck.check.dmarc;

import io.github.potwings.mailcheck.api.Check;
import io.github.potwings.mailcheck.api.CheckContext;
import io.github.potwings.mailcheck.api.CheckResult;
import io.github.potwings.mailcheck.api.CheckStatus;
import io.github.potwings.mailcheck.dns.DnsAnswer;
import io.github.potwings.mailcheck.dns.DnsQueryService;
import io.github.potwings.mailcheck.dns.RecordType;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * DMARC policy discovery and validation per RFC 7489, including the
 * organizational-domain fallback (§6.6.3) for subdomain inputs.
 */
public class DmarcCheck implements Check {

    private static final Set<String> POLICIES = Set.of("none", "quarantine", "reject");

    private final DnsQueryService dns;
    private final OrgDomainResolver orgResolver;

    public DmarcCheck(DnsQueryService dns, OrgDomainResolver orgResolver) {
        this.dns = dns;
        this.orgResolver = orgResolver;
    }

    @Override
    public String id() {
        return "dmarc";
    }

    @Override
    public String title() {
        return "DMARC";
    }

    private static boolean isDmarcRecord(String txt) {
        return txt.trim().toLowerCase(Locale.ROOT).startsWith("v=dmarc1");
    }

    @Override
    public CheckResult run(CheckContext ctx) {
        CheckResult.Builder b = CheckResult.builder(id(), title());
        String domain = ctx.domain();

        DnsAnswer ans = dns.query("_dmarc." + domain, RecordType.TXT);
        if (ans.failed()) {
            return b.status(CheckStatus.ERROR).evidence("_dmarc." + domain + " TXT 조회 실패 (" + ans.rcode() + ")").build();
        }
        List<String> records = ans.values().stream().filter(DmarcCheck::isDmarcRecord).toList();
        boolean fromOrgFallback = false;
        String policyDomain = domain;

        if (records.isEmpty()) {
            String org = orgResolver.organizationalDomain(domain);
            if (!org.equalsIgnoreCase(domain)) {
                DnsAnswer orgAns = dns.query("_dmarc." + org, RecordType.TXT);
                if (!orgAns.failed()) {
                    records = orgAns.values().stream().filter(DmarcCheck::isDmarcRecord).toList();
                    if (!records.isEmpty()) {
                        fromOrgFallback = true;
                        policyDomain = org;
                        b.evidence("_dmarc." + domain + " 에 레코드 없음 → 조직 도메인 " + org
                                + " 의 정책 적용 (RFC 7489 §6.6.3)");
                    }
                }
            }
        }

        if (records.isEmpty()) {
            return b.status(CheckStatus.FAIL)
                    .evidence("_dmarc TXT 레코드가 없음 (조직 도메인 포함)")
                    .guidance("_dmarc." + domain + " 에 \"v=DMARC1; p=none; rua=mailto:...\" 부터 시작해 단계적으로 강화하세요")
                    .build();
        }
        if (records.size() > 1) {
            b.status(CheckStatus.FAIL)
                    .evidence("DMARC 레코드가 " + records.size() + "개 존재 — 수신 서버는 전부 무시함 (RFC 7489 §6.6.3)")
                    .guidance("DMARC 레코드를 하나만 남기세요");
            records.forEach(r -> b.evidence("레코드: " + r));
            return b.build();
        }

        String record = records.get(0);
        b.evidence("레코드: " + record + (fromOrgFallback ? "  (출처: _dmarc." + policyDomain + ")" : ""));

        Map<String, String> tags = parseTags(record);
        String p = tags.get("p");
        if (p == null || !POLICIES.contains(p)) {
            return b.status(CheckStatus.FAIL)
                    .evidence(p == null ? "필수 태그 p= 가 없음" : "p= 값이 유효하지 않음: " + p)
                    .guidance("p=none / quarantine / reject 중 하나를 지정하세요")
                    .build();
        }

        // Subdomain covered by the org-domain record → sp (when present) governs it.
        String effective = p;
        if (fromOrgFallback && tags.containsKey("sp")) {
            effective = tags.get("sp");
            b.evidence("서브도메인이므로 sp=" + effective + " 가 적용됨");
            if (!POLICIES.contains(effective)) {
                return b.status(CheckStatus.FAIL).evidence("sp= 값이 유효하지 않음: " + effective).build();
            }
        }

        switch (effective) {
            case "none" -> b.atLeast(CheckStatus.WARN)
                    .evidence("적용 정책: " + effective + " — 모니터링 전용, 위조 메일이 차단되지 않음")
                    .guidance("리포트 확인 후 p=quarantine → p=reject 로 단계적 강화를 권장합니다");
            case "quarantine" -> b.evidence("적용 정책: quarantine — 실패 메일 격리");
            case "reject" -> b.evidence("적용 정책: reject — 실패 메일 거부 (권장 최종 상태)");
            default -> {
            }
        }

        if (tags.containsKey("sp") && !fromOrgFallback) {
            b.evidence("서브도메인 정책 sp=" + tags.get("sp"));
        }

        if (tags.containsKey("rua")) {
            String rua = tags.get("rua");
            b.evidence("집계 리포트 rua=" + rua);
            if (!rua.toLowerCase(Locale.ROOT).contains("mailto:")) {
                b.atLeast(CheckStatus.WARN).evidence("rua 값에 mailto: URI가 없음");
            }
        } else {
            b.atLeast(CheckStatus.WARN)
                    .evidence("rua= 미설정 — 집계 리포트를 받지 못해 정책 강화 판단 근거가 없음")
                    .guidance("rua=mailto:dmarc-reports@... 를 추가하세요");
        }
        if (tags.containsKey("ruf")) {
            b.evidence("실패 리포트 ruf=" + tags.get("ruf"));
        }

        verifyExternalReportDestinations(tags, policyDomain, b);

        if (tags.containsKey("pct")) {
            try {
                int pct = Integer.parseInt(tags.get("pct"));
                if (pct < 100) {
                    b.atLeast(CheckStatus.WARN)
                            .evidence("pct=" + pct + " — 정책이 메일의 " + pct + "%에만 적용됨");
                }
            } catch (NumberFormatException e) {
                b.atLeast(CheckStatus.WARN).evidence("pct 값이 숫자가 아님: " + tags.get("pct"));
            }
        }

        describeAlignment(tags, "adkim", "DKIM", b);
        describeAlignment(tags, "aspf", "SPF", b);

        return b.build();
    }

    /**
     * RFC 7489 §7.1 — a rua/ruf destination in another organization must publish
     * {@code <policyDomain>._report._dmarc.<destination>} TXT, or receivers
     * silently drop the reports.
     */
    private void verifyExternalReportDestinations(Map<String, String> tags, String policyDomain, CheckResult.Builder b) {
        String policyOrg = orgResolver.organizationalDomain(policyDomain).toLowerCase(Locale.ROOT);
        Set<String> externals = new LinkedHashSet<>();
        for (String tag : List.of("rua", "ruf")) {
            String value = tags.get(tag);
            if (value == null) {
                continue;
            }
            for (String uri : value.split(",")) {
                String u = uri.trim().toLowerCase(Locale.ROOT);
                if (!u.startsWith("mailto:")) {
                    continue;
                }
                String addr = u.substring("mailto:".length());
                int bang = addr.indexOf('!'); // mailto:a@b.com!10m — 리포트 크기 제한 접미사
                if (bang >= 0) {
                    addr = addr.substring(0, bang);
                }
                int at = addr.lastIndexOf('@');
                if (at <= 0 || at == addr.length() - 1) {
                    continue;
                }
                String dest = addr.substring(at + 1);
                if (!orgResolver.organizationalDomain(dest).toLowerCase(Locale.ROOT).equals(policyOrg)) {
                    externals.add(dest);
                }
            }
        }

        boolean anyMissing = false;
        for (String dest : externals) {
            String qname = policyDomain + "._report._dmarc." + dest;
            DnsAnswer ans = dns.query(qname, RecordType.TXT);
            if (ans.failed()) {
                b.atLeast(CheckStatus.WARN)
                        .evidence("외부 리포트 승인 확인 불가: " + qname + " TXT 조회 실패 (" + ans.rcode() + ")");
                continue;
            }
            if (ans.values().stream().anyMatch(DmarcCheck::isDmarcRecord)) {
                b.evidence("외부 리포트 승인 확인: " + dest + " 가 " + policyDomain + " 의 리포트 수신을 승인함");
            } else {
                anyMissing = true;
                b.atLeast(CheckStatus.WARN)
                        .evidence("외부 리포트 승인 레코드 없음: " + qname + " TXT — " + dest
                                + " 수신 서버가 리포트를 조용히 폐기함 (RFC 7489 §7.1)");
            }
        }
        if (anyMissing) {
            b.guidance("리포트 수신 도메인의 DNS에 <정책도메인>._report._dmarc.<수신도메인> TXT \"v=DMARC1\" 레코드를 추가하세요. "
                    + "외부 DMARC 리포트 서비스를 쓴다면 해당 서비스의 승인 레코드 등록 안내를 따르세요");
        }
    }

    private static void describeAlignment(Map<String, String> tags, String tag, String label, CheckResult.Builder b) {
        String v = tags.get(tag);
        if (v == null) {
            b.evidence(label + " alignment " + tag + " 미지정 → 기본값 r(relaxed)");
            return;
        }
        if (v.equals("r") || v.equals("s")) {
            b.evidence(label + " alignment " + tag + "=" + v + (v.equals("s") ? " (strict)" : " (relaxed)"));
        } else {
            b.atLeast(CheckStatus.WARN).evidence(tag + " 값이 유효하지 않음: " + v);
        }
    }

    private static Map<String, String> parseTags(String record) {
        Map<String, String> tags = new LinkedHashMap<>();
        for (String part : record.split(";")) {
            String p = part.trim();
            int eq = p.indexOf('=');
            if (eq > 0) {
                tags.put(p.substring(0, eq).trim().toLowerCase(Locale.ROOT), p.substring(eq + 1).trim());
            }
        }
        return tags;
    }
}
