package io.github.potwings.mailcheck.mail.check.dmarc;

import io.github.potwings.mailcheck.api.Check;
import io.github.potwings.mailcheck.api.CheckContext;
import io.github.potwings.mailcheck.api.CheckResult;
import io.github.potwings.mailcheck.api.CheckStatus;
import io.github.potwings.mailcheck.check.dmarc.OrgDomainResolver;
import io.github.potwings.mailcheck.check.spf.SpfEvaluator;
import io.github.potwings.mailcheck.check.spf.SpfRecordParser;
import io.github.potwings.mailcheck.dns.DnsAnswer;
import io.github.potwings.mailcheck.dns.DnsQueryService;
import io.github.potwings.mailcheck.dns.RecordType;
import io.github.potwings.mailcheck.mail.check.dkim.DkimVerificationSupport;

import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * DMARC alignment verified against the real mail (RFC 7489 §3.1): SPF identity
 * (MAIL FROM, or HELO for a bounce) and verified DKIM d= domains are compared
 * to the From: domain under the record's aspf/adkim modes. This separates
 * "record exists" (DmarcCheck) from "mail actually passes DMARC".
 */
public class DmarcAlignmentCheck implements Check {

    private static final Pattern HOSTNAME =
            Pattern.compile("^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z][a-z0-9-]{1,62}$");

    private final DnsQueryService dns;
    private final OrgDomainResolver orgResolver;
    private final SpfRecordParser parser = new SpfRecordParser();
    private final SpfEvaluator evaluator;
    private final DkimVerificationSupport dkim;

    public DmarcAlignmentCheck(DnsQueryService dns, OrgDomainResolver orgResolver) {
        this.dns = dns;
        this.orgResolver = orgResolver;
        this.evaluator = new SpfEvaluator(dns);
        this.dkim = new DkimVerificationSupport(dns);
    }

    @Override
    public String id() {
        return "dmarc-alignment";
    }

    @Override
    public String title() {
        return "DMARC Alignment";
    }

    @Override
    public CheckResult run(CheckContext ctx) {
        CheckResult.Builder b = CheckResult.builder(id(), title());
        if (!ctx.hasMailSession() || !ctx.hasEml()) {
            return b.status(CheckStatus.SKIP)
                    .evidence("SMTP 세션 정보와 메일 원문이 있어야 검사할 수 있음 — 실메일 수신 시 자동 수행")
                    .build();
        }
        String fromDomain = ctx.domain();

        Modes modes = discoverModes(fromDomain);
        b.evidence("From 도메인: " + fromDomain + " / alignment 모드: aspf=" + modes.aspf()
                + ", adkim=" + modes.adkim()
                + (modes.recordFound() ? "" : " (DMARC 레코드 없음 — 기본값 relaxed 가정)"));
        if (!modes.recordFound()) {
            b.evidence("DMARC 레코드가 없어 수신 서버는 아래 판정을 적용하지 않음 — 도입 대비 참고용");
        }

        boolean spfPass = false;
        boolean spfAligned = false;
        String spfDomain = resolveSpfIdentityDomain(ctx.mailSession());
        if (spfDomain == null) {
            b.evidence("SPF identity를 확정할 수 없음 (MAIL FROM이 비어 있고 HELO도 유효한 호스트명이 아님)");
        } else if (!ctx.hasTargetIps()) {
            b.evidence("세션 접속 IP가 없어 SPF 평가 불가");
        } else {
            spfAligned = aligned(spfDomain, fromDomain, modes.aspf());
            SpfEvaluator.Verdict verdict = evaluateSpf(spfDomain, ctx);
            spfPass = verdict == SpfEvaluator.Verdict.PASS;
            b.evidence("SPF: " + verdict.name().toLowerCase(Locale.ROOT) + " (평가 도메인 " + spfDomain
                    + ") / alignment: " + (spfAligned ? "일치"
                    : "불일치 (aspf=" + modes.aspf() + ("s".equals(modes.aspf())
                    ? " — From 도메인과 정확히 같아야 함)" : " — 조직 도메인이 다름)")));
        }

        boolean dkimLeg = false;
        DkimVerificationSupport.Outcome o = dkim.verify(ctx.emlPath());
        if (o.error() != null) {
            b.atLeast(CheckStatus.ERROR).evidence("DKIM 재검증 실패: " + o.error());
        } else if (o.noSignature()) {
            b.evidence("DKIM: 서명 없음 — DKIM alignment 평가 불가");
        } else if (o.passedDomains().isEmpty()) {
            b.evidence("DKIM: 유효한 서명 없음 — DKIM alignment 평가 불가");
        } else {
            List<String> alignedDomains = o.passedDomains().stream()
                    .filter(d -> aligned(d, fromDomain, modes.adkim()))
                    .toList();
            dkimLeg = !alignedDomains.isEmpty();
            b.evidence("DKIM: 검증 통과 d=" + String.join(", ", o.passedDomains())
                    + " / alignment: " + (dkimLeg ? "일치" : "불일치 (adkim=" + modes.adkim() + ")"));
        }

        boolean spfLeg = spfPass && spfAligned;
        if (spfLeg || dkimLeg) {
            b.evidence("DMARC 판정: pass — " + (spfLeg && dkimLeg ? "SPF·DKIM 모두"
                    : spfLeg ? "SPF" : "DKIM") + " alignment 충족 (둘 중 하나면 통과)");
        } else {
            b.status(CheckStatus.FAIL)
                    .evidence("DMARC 판정: fail — SPF·DKIM 어느 쪽도 「인증 통과 + From 도메인 정렬」을 충족하지 못함");
            if (spfPass && !spfAligned) {
                b.guidance("SPF는 통과했지만 MAIL FROM 도메인이 From 도메인과 정렬되지 않았습니다 — "
                        + "봉투 발신 주소(envelope from)를 From과 같은 도메인으로 맞추세요");
            }
            if (!o.passedDomains().isEmpty() && !dkimLeg) {
                b.guidance("DKIM은 통과했지만 서명 도메인(d=)이 From 도메인과 정렬되지 않았습니다 — "
                        + "From 도메인의 키로 서명(d=" + fromDomain + ")을 추가하세요");
            }
            if (!spfPass && o.passedDomains().isEmpty()) {
                b.guidance("SPF와 DKIM 검사부터 통과시켜야 DMARC alignment를 충족할 수 있습니다 — 두 검사 카드의 가이드를 먼저 적용하세요");
            }
        }
        return b.build();
    }

    private record Modes(String aspf, String adkim, boolean recordFound) {
    }

    /** aspf/adkim from the DMARC record, with the org-domain fallback (RFC 7489 §6.6.3). */
    private Modes discoverModes(String fromDomain) {
        List<String> records = dmarcRecords(fromDomain);
        if (records.isEmpty()) {
            String org = orgResolver.organizationalDomain(fromDomain);
            if (!org.equalsIgnoreCase(fromDomain)) {
                records = dmarcRecords(org);
            }
        }
        if (records.size() != 1) {
            return new Modes("r", "r", false);
        }
        String aspf = "r";
        String adkim = "r";
        for (String part : records.get(0).split(";")) {
            int eq = part.indexOf('=');
            if (eq <= 0) {
                continue;
            }
            String name = part.substring(0, eq).trim().toLowerCase(Locale.ROOT);
            String value = part.substring(eq + 1).trim().toLowerCase(Locale.ROOT);
            if (name.equals("aspf") && (value.equals("r") || value.equals("s"))) {
                aspf = value;
            } else if (name.equals("adkim") && (value.equals("r") || value.equals("s"))) {
                adkim = value;
            }
        }
        return new Modes(aspf, adkim, true);
    }

    private List<String> dmarcRecords(String domain) {
        DnsAnswer ans = dns.query("_dmarc." + domain, RecordType.TXT);
        if (ans.failed()) {
            return List.of();
        }
        return ans.values().stream()
                .filter(v -> v.trim().toLowerCase(Locale.ROOT).startsWith("v=dmarc1"))
                .toList();
    }

    /** SPF identity domain per RFC 7489 §3.1.2: MAIL FROM, or postmaster@HELO for a bounce. */
    private static String resolveSpfIdentityDomain(CheckContext.MailSession session) {
        String mailFromDomain = session.mailFromDomain();
        if (mailFromDomain != null) {
            return mailFromDomain;
        }
        String helo = session.helo() == null ? "" : session.helo().trim().toLowerCase(Locale.ROOT);
        return HOSTNAME.matcher(helo).matches() ? helo : null;
    }

    private SpfEvaluator.Verdict evaluateSpf(String spfDomain, CheckContext ctx) {
        DnsAnswer ans = dns.query(spfDomain, RecordType.TXT);
        if (ans.failed()) {
            return SpfEvaluator.Verdict.TEMPERROR;
        }
        List<String> spfRecords = ans.values().stream().filter(SpfRecordParser::isSpfRecord).toList();
        if (spfRecords.size() != 1) {
            return spfRecords.isEmpty() ? SpfEvaluator.Verdict.NEUTRAL : SpfEvaluator.Verdict.PERMERROR;
        }
        SpfRecordParser.ParseResult parsed = parser.parse(spfRecords.get(0));
        if (!parsed.errors().isEmpty()) {
            return SpfEvaluator.Verdict.PERMERROR;
        }
        CheckContext.MailSession ms = ctx.mailSession();
        String sender = ms.bounce() ? "postmaster@" + spfDomain : ms.mailFrom();
        SpfEvaluator.Evaluation ev = evaluator.evaluate(ctx.targetIps().get(0), spfDomain,
                parsed.terms(), new SpfEvaluator.SmtpSession(sender, ms.helo()));
        return ev.verdict();
    }

    private boolean aligned(String candidate, String fromDomain, String mode) {
        if (candidate.equalsIgnoreCase(fromDomain)) {
            return true;
        }
        if ("s".equals(mode)) {
            return false;
        }
        return orgResolver.organizationalDomain(candidate)
                .equalsIgnoreCase(orgResolver.organizationalDomain(fromDomain));
    }
}
