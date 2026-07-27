package io.github.potwings.mailcheck.mail.check.dmarc;

import io.github.potwings.mailcheck.api.CheckContext;
import io.github.potwings.mailcheck.api.CheckResult;
import io.github.potwings.mailcheck.api.CheckStatus;
import io.github.potwings.mailcheck.check.dmarc.OrgDomainResolver;
import io.github.potwings.mailcheck.dns.DnsAnswer;
import io.github.potwings.mailcheck.dns.DnsQueryService;
import io.github.potwings.mailcheck.dns.DnsRcode;
import io.github.potwings.mailcheck.dns.DnsRecordData;
import io.github.potwings.mailcheck.dns.RecordType;
import io.github.potwings.mailcheck.mail.check.EmlFixtures;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;

import java.nio.file.Path;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class DmarcAlignmentCheckTest {

    private static final String FROM_DOMAIN = "example.com";
    private static final String IP = "203.0.113.5";

    @TempDir
    Path tempDir;

    private DnsQueryService dns;
    private DmarcAlignmentCheck check;

    @BeforeEach
    void setUp() {
        dns = mock(DnsQueryService.class);
        // 미지정 조회는 NXDOMAIN — 각 테스트가 필요한 레코드만 세팅
        when(dns.query(Mockito.anyString(), Mockito.any()))
                .thenReturn(DnsAnswer.of(DnsRcode.NXDOMAIN));
        check = new DmarcAlignmentCheck(dns, new OrgDomainResolver());
    }

    private static DnsAnswer answer(String... values) {
        return new DnsAnswer(DnsRcode.NOERROR,
                Arrays.stream(values).map(v -> new DnsRecordData(v, 300)).toList());
    }

    private CheckResult run(Path emlPath, String mailFrom) {
        return check.run(new CheckContext(FROM_DOMAIN, List.of(IP), "SMTP 세션 접속 IP", true,
                new CheckContext.MailSession(mailFrom, "mail.example.com"), emlPath));
    }

    @Test
    void 세션이나_eml이_없으면_SKIP() {
        CheckResult r = check.run(new CheckContext(FROM_DOMAIN, List.of(IP), "사용자 입력"));

        assertThat(r.status()).isEqualTo(CheckStatus.SKIP);
    }

    @Test
    void SPF_pass_및_정렬이면_PASS() {
        when(dns.query("_dmarc." + FROM_DOMAIN, RecordType.TXT))
                .thenReturn(answer("v=DMARC1; p=reject"));
        when(dns.query(FROM_DOMAIN, RecordType.TXT))
                .thenReturn(answer("v=spf1 ip4:" + IP + " -all"));
        Path eml = EmlFixtures.write(tempDir, EmlFixtures.BASE_EML);

        CheckResult r = run(eml, "user@" + FROM_DOMAIN);

        assertThat(r.status()).isEqualTo(CheckStatus.PASS);
        assertThat(r.evidence()).anyMatch(e -> e.contains("DMARC 판정: pass"));
        assertThat(r.evidence()).anyMatch(e -> e.contains("SPF: pass"));
    }

    @Test
    void SPF는_통과했지만_정렬_불일치면_FAIL_및_봉투_가이드() {
        when(dns.query("_dmarc." + FROM_DOMAIN, RecordType.TXT))
                .thenReturn(answer("v=DMARC1; p=reject"));
        when(dns.query("bulk-sender.net", RecordType.TXT))
                .thenReturn(answer("v=spf1 ip4:" + IP + " -all"));
        Path eml = EmlFixtures.write(tempDir, EmlFixtures.BASE_EML);

        CheckResult r = run(eml, "bounce@bulk-sender.net");

        assertThat(r.status()).isEqualTo(CheckStatus.FAIL);
        assertThat(r.evidence()).anyMatch(e -> e.contains("alignment: 불일치"));
        assertThat(r.guidance()).anyMatch(g -> g.contains("envelope from"));
    }

    @Test
    void SPF가_실패해도_정렬된_DKIM이_통과하면_PASS() {
        when(dns.query("_dmarc." + FROM_DOMAIN, RecordType.TXT))
                .thenReturn(answer("v=DMARC1; p=reject"));
        // SPF 레코드 없음(NXDOMAIN 기본) → SPF leg 불충족
        KeyPair kp = EmlFixtures.rsaKeyPair(2048);
        when(dns.query("sel._domainkey." + FROM_DOMAIN, RecordType.TXT))
                .thenReturn(answer(EmlFixtures.publicKeyTxt(kp)));
        Path eml = EmlFixtures.write(tempDir,
                EmlFixtures.sign(EmlFixtures.BASE_EML, kp, FROM_DOMAIN, "sel"));

        CheckResult r = run(eml, "user@" + FROM_DOMAIN);

        assertThat(r.status()).isEqualTo(CheckStatus.PASS);
        assertThat(r.evidence()).anyMatch(e -> e.contains("DKIM: 검증 통과"));
        assertThat(r.evidence()).anyMatch(e -> e.contains("DMARC 판정: pass"));
    }

    @Test
    void relaxed면_서브도메인_MAIL_FROM도_정렬로_본다() {
        when(dns.query("_dmarc." + FROM_DOMAIN, RecordType.TXT))
                .thenReturn(answer("v=DMARC1; p=none"));
        when(dns.query("mail.example.com", RecordType.TXT))
                .thenReturn(answer("v=spf1 ip4:" + IP + " -all"));
        Path eml = EmlFixtures.write(tempDir, EmlFixtures.BASE_EML);

        CheckResult r = run(eml, "bounce@mail.example.com");

        assertThat(r.status()).isEqualTo(CheckStatus.PASS);
    }

    @Test
    void strict_aspf면_서브도메인_MAIL_FROM은_불일치() {
        when(dns.query("_dmarc." + FROM_DOMAIN, RecordType.TXT))
                .thenReturn(answer("v=DMARC1; p=none; aspf=s"));
        when(dns.query("mail.example.com", RecordType.TXT))
                .thenReturn(answer("v=spf1 ip4:" + IP + " -all"));
        Path eml = EmlFixtures.write(tempDir, EmlFixtures.BASE_EML);

        CheckResult r = run(eml, "bounce@mail.example.com");

        assertThat(r.status()).isEqualTo(CheckStatus.FAIL);
        assertThat(r.evidence()).anyMatch(e -> e.contains("aspf=s"));
    }

    @Test
    void DMARC_레코드가_없으면_참고용_안내를_남긴다() {
        when(dns.query(FROM_DOMAIN, RecordType.TXT))
                .thenReturn(answer("v=spf1 ip4:" + IP + " -all"));
        Path eml = EmlFixtures.write(tempDir, EmlFixtures.BASE_EML);

        CheckResult r = run(eml, "user@" + FROM_DOMAIN);

        assertThat(r.evidence()).anyMatch(e -> e.contains("DMARC 레코드가 없어"));
        assertThat(r.status()).isEqualTo(CheckStatus.PASS);
    }

    @Test
    void bounce면_HELO_도메인이_SPF_identity가_된다() {
        when(dns.query("_dmarc." + FROM_DOMAIN, RecordType.TXT))
                .thenReturn(answer("v=DMARC1; p=none"));
        when(dns.query("mail.example.com", RecordType.TXT))
                .thenReturn(answer("v=spf1 ip4:" + IP + " -all"));
        Path eml = EmlFixtures.write(tempDir, EmlFixtures.BASE_EML);

        CheckResult r = run(eml, null);

        assertThat(r.evidence()).anyMatch(e -> e.contains("평가 도메인 mail.example.com"));
        assertThat(r.status()).isEqualTo(CheckStatus.PASS);
    }
}
