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
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class PtrCheckTest {

    private static final String IP = "203.0.113.5";
    private static final String IP2 = "203.0.113.6";

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

    private CheckResult run(String... ips) {
        return check.run(new CheckContext("example.com", List.of(ips), "사용자 입력"));
    }

    @Test
    void 대상_IP가_없으면_SKIP() {
        CheckResult r = check.run(new CheckContext("example.com", List.of(), null));

        assertThat(r.status()).isEqualTo(CheckStatus.SKIP);
    }

    @Test
    void PTR이_없으면_FAIL() {
        when(dns.query(IP, RecordType.PTR)).thenReturn(DnsAnswer.of(DnsRcode.NXDOMAIN));

        assertThat(run(IP).status()).isEqualTo(CheckStatus.FAIL);
    }

    @Test
    void FCrDNS_왕복_확인되면_PASS() {
        when(dns.query(IP, RecordType.PTR)).thenReturn(answer("mail.example.com"));
        when(dns.query("mail.example.com", RecordType.A)).thenReturn(answer(IP));

        CheckResult r = run(IP);

        assertThat(r.status()).isEqualTo(CheckStatus.PASS);
        assertThat(r.evidence()).anyMatch(e -> e.contains("FCrDNS 확인"));
    }

    @Test
    void 정방향이_다른_IP로_가면_FAIL() {
        when(dns.query(IP, RecordType.PTR)).thenReturn(answer("mail.example.com"));
        when(dns.query("mail.example.com", RecordType.A)).thenReturn(answer("198.51.100.99"));

        CheckResult r = run(IP);

        assertThat(r.status()).isEqualTo(CheckStatus.FAIL);
        assertThat(r.evidence()).anyMatch(e -> e.contains("정방향 확인 실패"));
    }

    @Test
    void 다중_PTR_중_하나만_확인되면_WARN() {
        when(dns.query(IP, RecordType.PTR)).thenReturn(answer("mail.example.com", "other.example.com"));
        when(dns.query("mail.example.com", RecordType.A)).thenReturn(answer(IP));
        when(dns.query("other.example.com", RecordType.A)).thenReturn(DnsAnswer.of(DnsRcode.NXDOMAIN));

        CheckResult r = run(IP);

        assertThat(r.status()).isEqualTo(CheckStatus.WARN);
        assertThat(r.evidence()).anyMatch(e -> e.contains("PTR 레코드가 2개"));
    }

    @Test
    void 다중_IP_모두_확인되면_PASS() {
        when(dns.query(IP, RecordType.PTR)).thenReturn(answer("mail1.example.com"));
        when(dns.query("mail1.example.com", RecordType.A)).thenReturn(answer(IP));
        when(dns.query(IP2, RecordType.PTR)).thenReturn(answer("mail2.example.com"));
        when(dns.query("mail2.example.com", RecordType.A)).thenReturn(answer(IP2));

        CheckResult r = run(IP, IP2);

        assertThat(r.status()).isEqualTo(CheckStatus.PASS);
        assertThat(r.evidence()).anyMatch(e -> e.contains("[" + IP + "]") && e.contains("FCrDNS 확인"));
        assertThat(r.evidence()).anyMatch(e -> e.contains("[" + IP2 + "]") && e.contains("FCrDNS 확인"));
    }

    @Test
    void 다중_IP_중_하나라도_실패하면_FAIL() {
        when(dns.query(IP, RecordType.PTR)).thenReturn(answer("mail1.example.com"));
        when(dns.query("mail1.example.com", RecordType.A)).thenReturn(answer(IP));
        when(dns.query(IP2, RecordType.PTR)).thenReturn(DnsAnswer.of(DnsRcode.NXDOMAIN));

        CheckResult r = run(IP, IP2);

        assertThat(r.status()).isEqualTo(CheckStatus.FAIL);
        assertThat(r.evidence()).anyMatch(e -> e.contains("[" + IP2 + "]") && e.contains("PTR(역방향 DNS) 레코드가 없음"));
        assertThat(r.evidence()).anyMatch(e -> e.contains("[" + IP + "]") && e.contains("FCrDNS 확인"));
    }

    @Test
    void 다중_IP_조회_실패는_ERROR지만_다른_IP의_FAIL이_우선한다() {
        when(dns.query(IP, RecordType.PTR)).thenReturn(DnsAnswer.of(DnsRcode.TIMEOUT));
        when(dns.query(IP2, RecordType.PTR)).thenReturn(DnsAnswer.of(DnsRcode.NXDOMAIN));

        CheckResult r = run(IP, IP2);

        assertThat(r.status()).isEqualTo(CheckStatus.FAIL);
        assertThat(r.evidence()).anyMatch(e -> e.contains("PTR 조회 실패"));
    }

    @Test
    void 다중_IP에서_같은_유형의_가이드는_한번만_출력된다() {
        when(dns.query(IP, RecordType.PTR)).thenReturn(DnsAnswer.of(DnsRcode.NXDOMAIN));
        when(dns.query(IP2, RecordType.PTR)).thenReturn(DnsAnswer.of(DnsRcode.NXDOMAIN));

        CheckResult r = run(IP, IP2);

        assertThat(r.guidance()).filteredOn(g -> g.contains("역방향 DNS 등록")).hasSize(1);
    }

    @Test
    void 단일_IP면_증거에_IP_태그를_붙이지_않는다() {
        when(dns.query(IP, RecordType.PTR)).thenReturn(answer("mail.example.com"));
        when(dns.query("mail.example.com", RecordType.A)).thenReturn(answer(IP));

        CheckResult r = run(IP);

        assertThat(r.evidence()).noneMatch(e -> e.contains("[" + IP + "]"));
    }
}
