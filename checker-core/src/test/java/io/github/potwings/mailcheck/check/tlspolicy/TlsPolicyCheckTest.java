package io.github.potwings.mailcheck.check.tlspolicy;

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

import java.io.IOException;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class TlsPolicyCheckTest {

    private static final String DOMAIN = "example.com";
    private static final DnsAnswer EMPTY = DnsAnswer.of(DnsRcode.NOERROR);

    private static final String GOOD_POLICY = """
            version: STSv1
            mode: enforce
            mx: mx1.example.com
            mx: *.backup.example.com
            max_age: 604800
            """;

    private DnsQueryService dns;

    @BeforeEach
    void setUp() {
        dns = mock(DnsQueryService.class);
        when(dns.query(anyString(), eq(RecordType.TXT))).thenReturn(EMPTY);
        when(dns.query(anyString(), eq(RecordType.MX))).thenReturn(EMPTY);
    }

    private static DnsAnswer answer(String... values) {
        return new DnsAnswer(DnsRcode.NOERROR,
                Arrays.stream(values).map(v -> new DnsRecordData(v, 300)).toList());
    }

    private void stubSts(String record) {
        when(dns.query("_mta-sts." + DOMAIN, RecordType.TXT)).thenReturn(answer(record));
    }

    private void stubTlsRpt() {
        when(dns.query("_smtp._tls." + DOMAIN, RecordType.TXT))
                .thenReturn(answer("v=TLSRPTv1; rua=mailto:tls@example.com"));
    }

    private CheckResult run(PolicyFetcher fetcher) {
        return new TlsPolicyCheck(dns, fetcher).run(new CheckContext(DOMAIN, null, null));
    }

    @Test
    void 둘_다_미설정이면_WARN_및_도입_안내() {
        CheckResult r = run(d -> GOOD_POLICY);

        assertThat(r.status()).isEqualTo(CheckStatus.WARN);
        assertThat(r.evidence()).anyMatch(e -> e.contains("MTA-STS 미설정"));
        assertThat(r.evidence()).anyMatch(e -> e.contains("TLS-RPT 미설정"));
        assertThat(r.guidance()).anyMatch(g -> g.contains("mta-sts"));
    }

    @Test
    void enforce_정책과_MX가_일치하고_TLS_RPT도_있으면_PASS() {
        stubSts("v=STSv1; id=20260726T000000");
        stubTlsRpt();
        when(dns.query(DOMAIN, RecordType.MX))
                .thenReturn(answer("10 mx1.example.com", "20 relay.backup.example.com"));

        CheckResult r = run(d -> GOOD_POLICY);

        assertThat(r.status()).isEqualTo(CheckStatus.PASS);
        assertThat(r.evidence()).anyMatch(e -> e.contains("mode=enforce"));
        assertThat(r.evidence()).anyMatch(e -> e.contains("모든 MX가 정책 mx 목록과 일치"));
    }

    @Test
    void TXT는_있는데_정책_파일을_가져올_수_없으면_FAIL() {
        stubSts("v=STSv1; id=1");
        stubTlsRpt();

        CheckResult r = run(d -> {
            throw new IOException("HTTP 404");
        });

        assertThat(r.status()).isEqualTo(CheckStatus.FAIL);
        assertThat(r.evidence()).anyMatch(e -> e.contains("가져올 수 없음"));
    }

    @Test
    void mode_testing은_WARN과_enforce_전환_안내() {
        stubSts("v=STSv1; id=1");
        stubTlsRpt();
        when(dns.query(DOMAIN, RecordType.MX)).thenReturn(answer("10 mx1.example.com"));

        CheckResult r = run(d -> "version: STSv1\nmode: testing\nmx: mx1.example.com\nmax_age: 86400\n");

        assertThat(r.status()).isEqualTo(CheckStatus.WARN);
        assertThat(r.guidance()).anyMatch(g -> g.contains("enforce"));
    }

    @Test
    void enforce_모드에서_정책_mx와_불일치하는_MX는_FAIL() {
        stubSts("v=STSv1; id=1");
        stubTlsRpt();
        when(dns.query(DOMAIN, RecordType.MX)).thenReturn(answer("10 other-mx.example.net"));

        CheckResult r = run(d -> GOOD_POLICY);

        assertThat(r.status()).isEqualTo(CheckStatus.FAIL);
        assertThat(r.evidence()).anyMatch(e -> e.contains("불일치") && e.contains("other-mx.example.net"));
    }

    @Test
    void 와일드카드_패턴은_한_레이블만_매칭한다() {
        assertThat(TlsPolicyCheck.matchesMxPattern("mx1.example.com", "mx1.example.com")).isTrue();
        assertThat(TlsPolicyCheck.matchesMxPattern("a.backup.example.com", "*.backup.example.com")).isTrue();
        assertThat(TlsPolicyCheck.matchesMxPattern("a.b.backup.example.com", "*.backup.example.com")).isFalse();
        assertThat(TlsPolicyCheck.matchesMxPattern("backup.example.com", "*.backup.example.com")).isFalse();
    }

    @Test
    void TLS_RPT에_rua가_없으면_WARN() {
        stubSts("v=STSv1; id=1");
        when(dns.query(DOMAIN, RecordType.MX)).thenReturn(answer("10 mx1.example.com"));
        when(dns.query("_smtp._tls." + DOMAIN, RecordType.TXT)).thenReturn(answer("v=TLSRPTv1"));

        CheckResult r = run(d -> GOOD_POLICY);

        assertThat(r.status()).isEqualTo(CheckStatus.WARN);
        assertThat(r.evidence()).anyMatch(e -> e.contains("rua= 가 없음"));
    }

    @Test
    void 조회_실패는_ERROR로_표시하고_미설정으로_오판하지_않는다() {
        when(dns.query("_mta-sts." + DOMAIN, RecordType.TXT)).thenReturn(DnsAnswer.of(DnsRcode.TIMEOUT));
        stubTlsRpt();

        CheckResult r = run(d -> GOOD_POLICY);

        assertThat(r.status()).isEqualTo(CheckStatus.ERROR);
        assertThat(r.evidence()).noneMatch(e -> e.contains("MTA-STS 미설정"));
    }
}
