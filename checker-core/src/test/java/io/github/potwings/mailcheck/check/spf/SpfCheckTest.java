package io.github.potwings.mailcheck.check.spf;

import io.github.potwings.mailcheck.api.CheckContext;
import io.github.potwings.mailcheck.api.CheckResult;
import io.github.potwings.mailcheck.api.CheckStatus;
import io.github.potwings.mailcheck.dns.DnsAnswer;
import io.github.potwings.mailcheck.dns.DnsQueryService;
import io.github.potwings.mailcheck.dns.DnsRcode;
import io.github.potwings.mailcheck.dns.DnsRecordData;
import io.github.potwings.mailcheck.dns.RecordType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SpfCheckTest {

    private static final String DOMAIN = "example.com";

    private DnsQueryService dns;
    private SpfCheck check;

    @BeforeEach
    void setUp() {
        dns = mock(DnsQueryService.class);
        check = new SpfCheck(dns);
    }

    private static DnsAnswer txt(String... records) {
        return new DnsAnswer(DnsRcode.NOERROR,
                Arrays.stream(records).map(r -> new DnsRecordData(r, 300)).toList());
    }

    private CheckResult run() {
        return check.run(new CheckContext(DOMAIN, null, null));
    }

    @Test
    void SPF_레코드가_없으면_FAIL() {
        when(dns.query(DOMAIN, RecordType.TXT)).thenReturn(txt("google-site-verification=abc"));

        assertThat(run().status()).isEqualTo(CheckStatus.FAIL);
    }

    @Test
    void 도메인이_없으면_FAIL() {
        when(dns.query(DOMAIN, RecordType.TXT)).thenReturn(DnsAnswer.of(DnsRcode.NXDOMAIN));

        assertThat(run().status()).isEqualTo(CheckStatus.FAIL);
    }

    @Test
    void 조회_실패는_ERROR() {
        when(dns.query(DOMAIN, RecordType.TXT)).thenReturn(DnsAnswer.of(DnsRcode.TIMEOUT));

        assertThat(run().status()).isEqualTo(CheckStatus.ERROR);
    }

    @Test
    void 중복_SPF_레코드는_permerror로_FAIL() {
        when(dns.query(DOMAIN, RecordType.TXT))
                .thenReturn(txt("v=spf1 ip4:1.2.3.4 -all", "v=spf1 include:_spf.example.net ~all"));

        CheckResult r = run();

        assertThat(r.status()).isEqualTo(CheckStatus.FAIL);
        assertThat(r.evidence()).anyMatch(e -> e.contains("RFC 7208"));
    }

    @Test
    void 정상_레코드는_PASS_및_lookup_카운트_0() {
        when(dns.query(DOMAIN, RecordType.TXT)).thenReturn(txt("v=spf1 ip4:203.0.113.5 -all"));

        CheckResult r = run();

        assertThat(r.status()).isEqualTo(CheckStatus.PASS);
        assertThat(r.evidence()).anyMatch(e -> e.contains("DNS lookup: 0/10"));
    }

    @Test
    void plus_all_과허용은_WARN() {
        when(dns.query(DOMAIN, RecordType.TXT)).thenReturn(txt("v=spf1 ip4:203.0.113.5 +all"));

        CheckResult r = run();

        assertThat(r.status()).isEqualTo(CheckStatus.WARN);
        assertThat(r.evidence()).anyMatch(e -> e.contains("+all"));
    }

    @Test
    void 종단_all_누락은_WARN() {
        when(dns.query(DOMAIN, RecordType.TXT)).thenReturn(txt("v=spf1 ip4:203.0.113.5"));

        assertThat(run().status()).isEqualTo(CheckStatus.WARN);
    }

    @Test
    void lookup_10회_초과는_FAIL() {
        String record = "v=spf1 "
                + java.util.stream.IntStream.rangeClosed(1, 11)
                        .mapToObj(i -> "a:host" + i + ".example.com")
                        .reduce((a, c) -> a + " " + c).orElseThrow()
                + " -all";
        when(dns.query(DOMAIN, RecordType.TXT)).thenReturn(txt(record));

        CheckResult r = run();

        assertThat(r.status()).isEqualTo(CheckStatus.FAIL);
        assertThat(r.evidence()).anyMatch(e -> e.contains("10회 제한 초과"));
    }

    @Test
    void include_재귀_lookup을_합산한다() {
        when(dns.query(DOMAIN, RecordType.TXT)).thenReturn(txt("v=spf1 include:spf.example.net ~all"));
        when(dns.query("spf.example.net", RecordType.TXT))
                .thenReturn(txt("v=spf1 ip4:198.51.100.0/24 a mx -all"));

        CheckResult r = run();

        assertThat(r.status()).isEqualTo(CheckStatus.PASS);
        // include(1) + a(1) + mx(1) = 3
        assertThat(r.evidence()).anyMatch(e -> e.contains("DNS lookup: 3/10"));
    }

    @Test
    void include_대상에_SPF가_없으면_permerror로_FAIL() {
        when(dns.query(DOMAIN, RecordType.TXT)).thenReturn(txt("v=spf1 include:nospf.example.net ~all"));
        when(dns.query("nospf.example.net", RecordType.TXT)).thenReturn(txt("just some txt"));

        CheckResult r = run();

        assertThat(r.status()).isEqualTo(CheckStatus.FAIL);
        assertThat(r.evidence()).anyMatch(e -> e.contains("nospf.example.net"));
    }

    @Test
    void include_순환_참조는_FAIL() {
        when(dns.query(DOMAIN, RecordType.TXT)).thenReturn(txt("v=spf1 include:loop.example.net ~all"));
        when(dns.query("loop.example.net", RecordType.TXT))
                .thenReturn(txt("v=spf1 include:" + DOMAIN + " ~all"));

        CheckResult r = run();

        assertThat(r.status()).isEqualTo(CheckStatus.FAIL);
        assertThat(r.evidence()).anyMatch(e -> e.contains("순환"));
    }

    @Test
    void 세션_의존_매크로는_재귀를_생략하고_카운트만_반영() {
        when(dns.query(DOMAIN, RecordType.TXT))
                .thenReturn(txt("v=spf1 include:%{i}.spf.example.net ~all"));

        CheckResult r = run();

        assertThat(r.status()).isEqualTo(CheckStatus.PASS);
        assertThat(r.evidence()).anyMatch(e -> e.contains("매크로"));
        assertThat(r.evidence()).anyMatch(e -> e.contains("DNS lookup: 1/10"));
    }

    @Test
    void 구문_오류는_FAIL() {
        when(dns.query(DOMAIN, RecordType.TXT)).thenReturn(txt("v=spf1 ip4:203.0.113.5 badmech:x -all"));

        assertThat(run().status()).isEqualTo(CheckStatus.FAIL);
    }

    // ---- 사용자 입력 IP에 대한 check_host() 평가 ----

    private CheckResult runWithUserIps(String... ips) {
        return check.run(new CheckContext(DOMAIN, java.util.List.of(ips), "사용자 입력", true));
    }

    @Test
    void 사용자_IP가_SPF에_허용되면_PASS() {
        when(dns.query(DOMAIN, RecordType.TXT)).thenReturn(txt("v=spf1 ip4:203.0.113.0/24 -all"));

        CheckResult r = runWithUserIps("203.0.113.5");

        assertThat(r.status()).isEqualTo(CheckStatus.PASS);
        assertThat(r.evidence()).anyMatch(e -> e.contains("평가: pass"));
    }

    @Test
    void 사용자_IP가_SPF에_없으면_FAIL과_추가_안내() {
        when(dns.query(DOMAIN, RecordType.TXT)).thenReturn(txt("v=spf1 ip4:203.0.113.5 ~all"));

        CheckResult r = runWithUserIps("198.51.100.9");

        assertThat(r.status()).isEqualTo(CheckStatus.FAIL);
        assertThat(r.evidence()).anyMatch(e -> e.contains("softfail"));
        assertThat(r.guidance()).anyMatch(g -> g.contains("ip4:<IP>"));
    }

    @Test
    void 다중_IP는_worst_of_집계와_IP_태그() {
        when(dns.query(DOMAIN, RecordType.TXT)).thenReturn(txt("v=spf1 ip4:203.0.113.5 -all"));

        CheckResult r = runWithUserIps("203.0.113.5", "198.51.100.9");

        assertThat(r.status()).isEqualTo(CheckStatus.FAIL);
        assertThat(r.evidence()).anyMatch(e -> e.equals("[203.0.113.5] 발신 IP 평가: pass (매칭: ip4:203.0.113.5)"));
        assertThat(r.evidence()).anyMatch(e -> e.startsWith("[198.51.100.9] 발신 IP 평가: fail"));
    }

    // ---- 실메일 세션(MailSession) 기반 평가 도메인 결정 ----

    private CheckResult runWithSession(String mailFrom, String helo, String... ips) {
        return check.run(new CheckContext(DOMAIN, java.util.List.of(ips), "SMTP 세션 접속 IP",
                true, new CheckContext.MailSession(mailFrom, helo)));
    }

    @Test
    void 세션이_있으면_MAIL_FROM_도메인으로_SPF를_평가() {
        when(dns.query("sender.example", RecordType.TXT))
                .thenReturn(txt("v=spf1 ip4:203.0.113.5 -all"));

        CheckResult r = runWithSession("user@sender.example", "mail.sender.example", "203.0.113.5");

        assertThat(r.status()).isEqualTo(CheckStatus.PASS);
        assertThat(r.evidence()).anyMatch(e -> e.contains("sender.example") && e.contains("MAIL FROM 기준"));
        assertThat(r.evidence()).anyMatch(e -> e.contains("평가: pass"));
    }

    @Test
    void bounce면_HELO_도메인으로_폴백해_평가() {
        when(dns.query("mail.sender.example", RecordType.TXT))
                .thenReturn(txt("v=spf1 ip4:203.0.113.5 -all"));

        CheckResult r = runWithSession(null, "mail.sender.example", "203.0.113.5");

        assertThat(r.status()).isEqualTo(CheckStatus.PASS);
        assertThat(r.evidence()).anyMatch(e -> e.contains("HELO 기준"));
    }

    @Test
    void bounce에_HELO가_주소_리터럴이면_ERROR() {
        CheckResult r = runWithSession("", "[203.0.113.5]", "203.0.113.5");

        assertThat(r.status()).isEqualTo(CheckStatus.ERROR);
        assertThat(r.evidence()).anyMatch(e -> e.contains("SPF 평가 도메인을 정할 수 없음"));
    }

    @Test
    void MX_도출_IP는_SPF_평가에_사용하지_않음() {
        when(dns.query(DOMAIN, RecordType.TXT)).thenReturn(txt("v=spf1 ip4:203.0.113.5 -all"));

        CheckResult r = check.run(new CheckContext(DOMAIN,
                java.util.List.of("192.0.2.1"), "MX(mx1)의 A 레코드에서 도출", false));

        assertThat(r.status()).isEqualTo(CheckStatus.PASS);
        assertThat(r.evidence()).anyMatch(e -> e.contains("발신 서버 IP를 입력하면"));
    }
}
