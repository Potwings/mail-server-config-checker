package io.github.potwings.mailcheck.check.rbl;

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

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class RblCheckTest {

    private static final String IP = "203.0.113.5";
    private static final String REVERSED = "5.113.0.203";
    private static final String IP2 = "203.0.113.6";
    private static final String REVERSED2 = "6.113.0.203";

    private DnsQueryService dns;

    @BeforeEach
    void setUp() {
        dns = mock(DnsQueryService.class);
    }

    private static DnsAnswer listedAnswer(String code) {
        return new DnsAnswer(DnsRcode.NOERROR, List.of(new DnsRecordData(code, 60)));
    }

    private CheckResult run(RblCheck check, String... ips) {
        return check.run(new CheckContext("example.com", List.of(ips), "사용자 입력"));
    }

    @Test
    void IP_옥텟_역순_변환() {
        assertThat(RblCheck.reverseOctets("1.2.3.4")).isEqualTo("4.3.2.1");
    }

    @Test
    void 대상_IP가_없으면_SKIP() {
        RblCheck check = new RblCheck(dns, List.of(new SpamCopProvider(true)));

        CheckResult r = check.run(new CheckContext("example.com", List.of(), null));

        assertThat(r.status()).isEqualTo(CheckStatus.SKIP);
    }

    @Test
    void 모든_RBL_미등재면_PASS() {
        when(dns.query(REVERSED + ".bl.spamcop.net", RecordType.A)).thenReturn(DnsAnswer.of(DnsRcode.NXDOMAIN));
        when(dns.query(REVERSED + ".b.barracudacentral.org", RecordType.A)).thenReturn(DnsAnswer.of(DnsRcode.NXDOMAIN));
        RblCheck check = new RblCheck(dns, List.of(new SpamCopProvider(true), new BarracudaProvider(true)));

        CheckResult r = run(check, IP);

        assertThat(r.status()).isEqualTo(CheckStatus.PASS);
        assertThat(r.evidence()).anyMatch(e -> e.contains("SpamCop: 미등재"));
    }

    @Test
    void 하나라도_등재되면_FAIL() {
        when(dns.query(REVERSED + ".bl.spamcop.net", RecordType.A)).thenReturn(listedAnswer("127.0.0.2"));
        when(dns.query(REVERSED + ".b.barracudacentral.org", RecordType.A)).thenReturn(DnsAnswer.of(DnsRcode.NXDOMAIN));
        RblCheck check = new RblCheck(dns, List.of(new SpamCopProvider(true), new BarracudaProvider(true)));

        CheckResult r = run(check, IP);

        assertThat(r.status()).isEqualTo(CheckStatus.FAIL);
        assertThat(r.evidence()).anyMatch(e -> e.contains("SpamCop: 등재됨"));
    }

    @Test
    void 조회_오류는_WARN이며_미등재로_처리되지_않는다() {
        when(dns.query(REVERSED + ".b.barracudacentral.org", RecordType.A)).thenReturn(DnsAnswer.of(DnsRcode.TIMEOUT));
        RblCheck check = new RblCheck(dns, List.of(new BarracudaProvider(true)));

        CheckResult r = run(check, IP);

        assertThat(r.status()).isEqualTo(CheckStatus.WARN);
        assertThat(r.evidence()).anyMatch(e -> e.contains("확인 불가"));
        assertThat(r.evidence()).noneMatch(e -> e.contains("Barracuda: 미등재"));
    }

    @Test
    void 비활성_프로바이더는_안내와_함께_건너뛴다() {
        RblCheck check = new RblCheck(dns, List.of(new SpamhausZenDqsProvider("")));

        CheckResult r = run(check, IP);

        assertThat(r.status()).isEqualTo(CheckStatus.SKIP);
        assertThat(r.evidence()).anyMatch(e -> e.contains("DQS 키"));
    }

    @Test
    void IPv6는_SKIP() {
        RblCheck check = new RblCheck(dns, List.of(new SpamCopProvider(true)));

        CheckResult r = run(check, "2001:db8::1");

        assertThat(r.status()).isEqualTo(CheckStatus.SKIP);
    }

    @Test
    void 다중_IP_모두_미등재면_PASS() {
        when(dns.query(REVERSED + ".bl.spamcop.net", RecordType.A)).thenReturn(DnsAnswer.of(DnsRcode.NXDOMAIN));
        when(dns.query(REVERSED2 + ".bl.spamcop.net", RecordType.A)).thenReturn(DnsAnswer.of(DnsRcode.NXDOMAIN));
        RblCheck check = new RblCheck(dns, List.of(new SpamCopProvider(true)));

        CheckResult r = run(check, IP, IP2);

        assertThat(r.status()).isEqualTo(CheckStatus.PASS);
        assertThat(r.evidence()).anyMatch(e -> e.contains("[" + IP + "] SpamCop: 미등재"));
        assertThat(r.evidence()).anyMatch(e -> e.contains("[" + IP2 + "] SpamCop: 미등재"));
    }

    @Test
    void 다중_IP_중_하나라도_등재되면_FAIL() {
        when(dns.query(REVERSED + ".bl.spamcop.net", RecordType.A)).thenReturn(DnsAnswer.of(DnsRcode.NXDOMAIN));
        when(dns.query(REVERSED2 + ".bl.spamcop.net", RecordType.A)).thenReturn(listedAnswer("127.0.0.2"));
        RblCheck check = new RblCheck(dns, List.of(new SpamCopProvider(true)));

        CheckResult r = run(check, IP, IP2);

        assertThat(r.status()).isEqualTo(CheckStatus.FAIL);
        assertThat(r.evidence()).anyMatch(e -> e.contains("[" + IP2 + "] SpamCop: 등재됨"));
    }

    @Test
    void IPv4와_IPv6가_섞이면_IPv4만_검사하고_IPv6는_제외_안내() {
        when(dns.query(REVERSED + ".bl.spamcop.net", RecordType.A)).thenReturn(DnsAnswer.of(DnsRcode.NXDOMAIN));
        RblCheck check = new RblCheck(dns, List.of(new SpamCopProvider(true)));

        CheckResult r = run(check, IP, "2001:db8::1");

        assertThat(r.status()).isEqualTo(CheckStatus.PASS);
        assertThat(r.evidence()).anyMatch(e -> e.contains("2001:db8::1") && e.contains("IPv6"));
    }

    @Test
    void 단일_IP면_증거에_IP_태그를_붙이지_않는다() {
        when(dns.query(REVERSED + ".bl.spamcop.net", RecordType.A)).thenReturn(DnsAnswer.of(DnsRcode.NXDOMAIN));
        RblCheck check = new RblCheck(dns, List.of(new SpamCopProvider(true)));

        CheckResult r = run(check, IP);

        assertThat(r.evidence()).noneMatch(e -> e.contains("[" + IP + "]"));
    }
}
