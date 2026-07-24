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
}
