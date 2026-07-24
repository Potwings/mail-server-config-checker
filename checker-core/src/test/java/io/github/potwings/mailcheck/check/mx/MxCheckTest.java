package io.github.potwings.mailcheck.check.mx;

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
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class MxCheckTest {

    private static final String DOMAIN = "example.com";
    private static final DnsAnswer EMPTY = DnsAnswer.of(DnsRcode.NOERROR);

    private DnsQueryService dns;
    private MxCheck check;

    @BeforeEach
    void setUp() {
        dns = mock(DnsQueryService.class);
        when(dns.query(anyString(), eq(RecordType.CNAME))).thenReturn(EMPTY);
        when(dns.query(anyString(), eq(RecordType.A))).thenReturn(EMPTY);
        when(dns.query(anyString(), eq(RecordType.AAAA))).thenReturn(EMPTY);
        check = new MxCheck(dns);
    }

    private static DnsAnswer answer(String... values) {
        return new DnsAnswer(DnsRcode.NOERROR,
                Arrays.stream(values).map(v -> new DnsRecordData(v, 300)).toList());
    }

    private CheckResult run() {
        return check.run(new CheckContext(DOMAIN, null, null));
    }

    @Test
    void 정상_MX와_A_해석은_PASS() {
        when(dns.query(DOMAIN, RecordType.MX)).thenReturn(answer("10 mx1.example.com", "20 mx2.example.com"));
        when(dns.query("mx1.example.com", RecordType.A)).thenReturn(answer("203.0.113.10"));
        when(dns.query("mx2.example.com", RecordType.A)).thenReturn(answer("203.0.113.11"));

        CheckResult r = run();

        assertThat(r.status()).isEqualTo(CheckStatus.PASS);
        assertThat(r.evidence()).anyMatch(e -> e.contains("mx1.example.com"));
    }

    @Test
    void MX가_CNAME이면_WARN_및_RFC_위반_명시() {
        when(dns.query(DOMAIN, RecordType.MX)).thenReturn(answer("10 mail.example.com"));
        when(dns.query("mail.example.com", RecordType.CNAME)).thenReturn(answer("real.example.com"));
        when(dns.query("mail.example.com", RecordType.A)).thenReturn(answer("203.0.113.10"));

        CheckResult r = run();

        assertThat(r.status()).isEqualTo(CheckStatus.WARN);
        assertThat(r.evidence()).anyMatch(e -> e.contains("RFC 5321"));
    }

    @Test
    void MX_없이_A만_있으면_암묵적_MX로_WARN() {
        when(dns.query(DOMAIN, RecordType.MX)).thenReturn(EMPTY);
        when(dns.query(DOMAIN, RecordType.A)).thenReturn(answer("203.0.113.10"));

        CheckResult r = run();

        assertThat(r.status()).isEqualTo(CheckStatus.WARN);
        assertThat(r.evidence()).anyMatch(e -> e.contains("암묵적"));
    }

    @Test
    void MX도_A도_없으면_FAIL() {
        when(dns.query(DOMAIN, RecordType.MX)).thenReturn(EMPTY);

        assertThat(run().status()).isEqualTo(CheckStatus.FAIL);
    }

    @Test
    void Null_MX는_WARN_및_RFC_7505_명시() {
        when(dns.query(DOMAIN, RecordType.MX)).thenReturn(answer("0 ."));

        CheckResult r = run();

        assertThat(r.status()).isEqualTo(CheckStatus.WARN);
        assertThat(r.evidence()).anyMatch(e -> e.contains("RFC 7505"));
    }

    @Test
    void 모든_MX_호스트가_해석_불가면_FAIL() {
        when(dns.query(DOMAIN, RecordType.MX)).thenReturn(answer("10 ghost.example.com"));

        assertThat(run().status()).isEqualTo(CheckStatus.FAIL);
    }

    @Test
    void 일부_MX_호스트만_해석_불가면_WARN() {
        when(dns.query(DOMAIN, RecordType.MX)).thenReturn(answer("10 mx1.example.com", "20 ghost.example.com"));
        when(dns.query("mx1.example.com", RecordType.A)).thenReturn(answer("203.0.113.10"));

        assertThat(run().status()).isEqualTo(CheckStatus.WARN);
    }
}
