package io.github.potwings.mailcheck.mail.check.dkim;

import io.github.potwings.mailcheck.api.CheckContext;
import io.github.potwings.mailcheck.api.CheckResult;
import io.github.potwings.mailcheck.api.CheckStatus;
import io.github.potwings.mailcheck.dns.DnsAnswer;
import io.github.potwings.mailcheck.dns.DnsQueryService;
import io.github.potwings.mailcheck.dns.DnsRcode;
import io.github.potwings.mailcheck.dns.DnsRecordData;
import io.github.potwings.mailcheck.dns.RecordType;
import io.github.potwings.mailcheck.mail.check.EmlFixtures;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class DkimCheckTest {

    private static final String DOMAIN = "example.com";
    private static final String SELECTOR = "sel";
    private static final String KEY_QNAME = SELECTOR + "._domainkey." + DOMAIN;

    @TempDir
    Path tempDir;

    private DnsQueryService dns;
    private DkimCheck check;

    @BeforeEach
    void setUp() {
        dns = mock(DnsQueryService.class);
        check = new DkimCheck(dns);
    }

    private static DnsAnswer answer(String... values) {
        return new DnsAnswer(DnsRcode.NOERROR,
                Arrays.stream(values).map(v -> new DnsRecordData(v, 300)).toList());
    }

    private CheckResult run(Path emlPath) {
        return check.run(new CheckContext(DOMAIN, List.of("203.0.113.5"), "SMTP 세션 접속 IP", true,
                new CheckContext.MailSession("user@example.com", "mail.example.com"), emlPath));
    }

    @Test
    void eml이_없으면_SKIP() {
        CheckResult r = check.run(new CheckContext(DOMAIN, List.of(), null));

        assertThat(r.status()).isEqualTo(CheckStatus.SKIP);
    }

    @Test
    void 서명_헤더가_없으면_FAIL() {
        Path eml = EmlFixtures.write(tempDir, EmlFixtures.BASE_EML);

        CheckResult r = run(eml);

        assertThat(r.status()).isEqualTo(CheckStatus.FAIL);
        assertThat(r.evidence()).anyMatch(e -> e.contains("DKIM-Signature 헤더가 없음"));
    }

    @Test
    void 유효한_서명이면_PASS_및_키_길이_증거() {
        KeyPair kp = EmlFixtures.rsaKeyPair(2048);
        when(dns.query(KEY_QNAME, RecordType.TXT)).thenReturn(answer(EmlFixtures.publicKeyTxt(kp)));
        Path eml = EmlFixtures.write(tempDir,
                EmlFixtures.sign(EmlFixtures.BASE_EML, kp, DOMAIN, SELECTOR));

        CheckResult r = run(eml);

        assertThat(r.status()).isEqualTo(CheckStatus.PASS);
        assertThat(r.evidence()).anyMatch(e -> e.contains("서명 검증 성공") && e.contains("d=" + DOMAIN));
        assertThat(r.evidence()).anyMatch(e -> e.contains("2048비트"));
    }

    @Test
    void 본문이_변조되면_FAIL() {
        KeyPair kp = EmlFixtures.rsaKeyPair(2048);
        when(dns.query(KEY_QNAME, RecordType.TXT)).thenReturn(answer(EmlFixtures.publicKeyTxt(kp)));
        String signed = EmlFixtures.sign(EmlFixtures.BASE_EML, kp, DOMAIN, SELECTOR);
        Path eml = EmlFixtures.write(tempDir, signed.replace("Hello DKIM", "Tampered!!"));

        CheckResult r = run(eml);

        assertThat(r.status()).isEqualTo(CheckStatus.FAIL);
        assertThat(r.evidence()).anyMatch(e -> e.contains("서명 검증 실패"));
    }

    @Test
    void 키가_폐기되면_FAIL_및_폐기_안내() {
        KeyPair kp = EmlFixtures.rsaKeyPair(2048);
        when(dns.query(KEY_QNAME, RecordType.TXT)).thenReturn(answer("v=DKIM1; k=rsa; p="));
        Path eml = EmlFixtures.write(tempDir,
                EmlFixtures.sign(EmlFixtures.BASE_EML, kp, DOMAIN, SELECTOR));

        CheckResult r = run(eml);

        assertThat(r.status()).isEqualTo(CheckStatus.FAIL);
        assertThat(r.evidence()).anyMatch(e -> e.contains("폐기"));
    }

    @Test
    void 테스트_모드_키는_WARN() {
        KeyPair kp = EmlFixtures.rsaKeyPair(2048);
        when(dns.query(KEY_QNAME, RecordType.TXT))
                .thenReturn(answer(EmlFixtures.publicKeyTxt(kp).replace("k=rsa;", "k=rsa; t=y;")));
        Path eml = EmlFixtures.write(tempDir,
                EmlFixtures.sign(EmlFixtures.BASE_EML, kp, DOMAIN, SELECTOR));

        CheckResult r = run(eml);

        assertThat(r.status()).isEqualTo(CheckStatus.WARN);
        assertThat(r.evidence()).anyMatch(e -> e.contains("t=y"));
    }

    @Test
    void RSA_1024비트_키는_WARN() {
        KeyPair kp = EmlFixtures.rsaKeyPair(1024);
        when(dns.query(KEY_QNAME, RecordType.TXT)).thenReturn(answer(EmlFixtures.publicKeyTxt(kp)));
        Path eml = EmlFixtures.write(tempDir,
                EmlFixtures.sign(EmlFixtures.BASE_EML, kp, DOMAIN, SELECTOR));

        CheckResult r = run(eml);

        assertThat(r.status()).isEqualTo(CheckStatus.WARN);
        assertThat(r.evidence()).anyMatch(e -> e.contains("1024비트"));
    }

    @Test
    void 키_레코드가_없으면_FAIL() {
        KeyPair kp = EmlFixtures.rsaKeyPair(2048);
        when(dns.query(KEY_QNAME, RecordType.TXT)).thenReturn(DnsAnswer.of(DnsRcode.NXDOMAIN));
        Path eml = EmlFixtures.write(tempDir,
                EmlFixtures.sign(EmlFixtures.BASE_EML, kp, DOMAIN, SELECTOR));

        CheckResult r = run(eml);

        assertThat(r.status()).isEqualTo(CheckStatus.FAIL);
        assertThat(r.evidence()).anyMatch(e -> e.contains("공개키 레코드가 없음"));
    }

    @Test
    void 태그_파싱은_공백을_무시한다() {
        var tags = DkimCheck.parseTags("v=DKIM1; k=rsa; t=y; p=AB CD\r\n EF");

        assertThat(tags.get("p")).isEqualTo("ABCDEF");
        assertThat(tags.get("t")).isEqualTo("y");
    }
}
