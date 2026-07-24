package io.github.potwings.mailcheck.check.ptr;

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

class PtrCheckTest {

    private static final String IP = "203.0.113.5";

    private DnsQueryService dns;
    private PtrCheck check;

    @BeforeEach
    void setUp() {
        dns = mock(DnsQueryService.class);
        check = new PtrCheck(dns);
    }

    private static DnsAnswer answer(String... values) {
        return new DnsAnswer(DnsRcode.NOERROR,
                Arrays.stream(values).map(v -> new DnsRecordData(v, 300)).toList());
    }

    private CheckResult run() {
        return check.run(new CheckContext("example.com", IP, "사용자 입력"));
    }

    @Test
    void 대상_IP가_없으면_SKIP() {
        CheckResult r = check.run(new CheckContext("example.com", null, null));

        assertThat(r.status()).isEqualTo(CheckStatus.SKIP);
    }

    @Test
    void PTR이_없으면_FAIL() {
        when(dns.query(IP, RecordType.PTR)).thenReturn(DnsAnswer.of(DnsRcode.NXDOMAIN));

        assertThat(run().status()).isEqualTo(CheckStatus.FAIL);
    }

    @Test
    void FCrDNS_왕복_확인되면_PASS() {
        when(dns.query(IP, RecordType.PTR)).thenReturn(answer("mail.example.com"));
        when(dns.query("mail.example.com", RecordType.A)).thenReturn(answer(IP));

        CheckResult r = run();

        assertThat(r.status()).isEqualTo(CheckStatus.PASS);
        assertThat(r.evidence()).anyMatch(e -> e.contains("FCrDNS 확인"));
    }

    @Test
    void 정방향이_다른_IP로_가면_FAIL() {
        when(dns.query(IP, RecordType.PTR)).thenReturn(answer("mail.example.com"));
        when(dns.query("mail.example.com", RecordType.A)).thenReturn(answer("198.51.100.99"));

        CheckResult r = run();

        assertThat(r.status()).isEqualTo(CheckStatus.FAIL);
        assertThat(r.evidence()).anyMatch(e -> e.contains("정방향 확인 실패"));
    }

    @Test
    void 다중_PTR_중_하나만_확인되면_WARN() {
        when(dns.query(IP, RecordType.PTR)).thenReturn(answer("mail.example.com", "other.example.com"));
        when(dns.query("mail.example.com", RecordType.A)).thenReturn(answer(IP));
        when(dns.query("other.example.com", RecordType.A)).thenReturn(DnsAnswer.of(DnsRcode.NXDOMAIN));

        CheckResult r = run();

        assertThat(r.status()).isEqualTo(CheckStatus.WARN);
        assertThat(r.evidence()).anyMatch(e -> e.contains("PTR 레코드가 2개"));
    }
}
