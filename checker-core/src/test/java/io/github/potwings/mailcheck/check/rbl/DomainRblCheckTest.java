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

class DomainRblCheckTest {

    private static final String DOMAIN = "example.com";
    private static final String QUERY = DOMAIN + ".testkey123.dbl.dq.spamhaus.net";

    private DnsQueryService dns;
    private DomainRblCheck check;

    @BeforeEach
    void setUp() {
        dns = mock(DnsQueryService.class);
        check = new DomainRblCheck(dns, List.of(new SpamhausDblProvider("testkey123")));
    }

    private static DnsAnswer listedAnswer(String code) {
        return new DnsAnswer(DnsRcode.NOERROR, List.of(new DnsRecordData(code, 60)));
    }

    private CheckResult run() {
        return check.run(new CheckContext(DOMAIN, List.of(), null));
    }

    @Test
    void 미등재면_PASS() {
        when(dns.query(QUERY, RecordType.A)).thenReturn(DnsAnswer.of(DnsRcode.NXDOMAIN));

        CheckResult r = run();

        assertThat(r.status()).isEqualTo(CheckStatus.PASS);
        assertThat(r.evidence()).anyMatch(e -> e.contains("미등재"));
    }

    @Test
    void 등재되면_FAIL이고_해제_가이드를_안내한다() {
        when(dns.query(QUERY, RecordType.A)).thenReturn(listedAnswer("127.0.1.2"));

        CheckResult r = run();

        assertThat(r.status()).isEqualTo(CheckStatus.FAIL);
        assertThat(r.evidence()).anyMatch(e -> e.contains("등재됨") && e.contains("스팸 도메인"));
        assertThat(r.guidance()).anyMatch(g -> g.contains("check.spamhaus.org"));
    }

    @Test
    void 악용된_정상_도메인_등재는_취약점_점검_가이드를_추가한다() {
        when(dns.query(QUERY, RecordType.A)).thenReturn(listedAnswer("127.0.1.102"));

        CheckResult r = run();

        assertThat(r.status()).isEqualTo(CheckStatus.FAIL);
        assertThat(r.guidance()).anyMatch(g -> g.contains("취약점"));
    }

    @Test
    void DQS_오류_코드는_WARN이며_미등재로_처리되지_않는다() {
        when(dns.query(QUERY, RecordType.A)).thenReturn(listedAnswer("127.255.255.254"));

        CheckResult r = run();

        assertThat(r.status()).isEqualTo(CheckStatus.WARN);
        assertThat(r.evidence()).anyMatch(e -> e.contains("확인 불가"));
        assertThat(r.evidence()).noneMatch(e -> e.endsWith(": 미등재"));
    }

    @Test
    void 키가_없으면_SKIP과_발급_안내() {
        DomainRblCheck noKey = new DomainRblCheck(dns, List.of(new SpamhausDblProvider("")));

        CheckResult r = noKey.run(new CheckContext(DOMAIN, List.of(), null));

        assertThat(r.status()).isEqualTo(CheckStatus.SKIP);
        assertThat(r.evidence()).anyMatch(e -> e.contains("DQS 키"));
    }

    @Test
    void 증거에_DQS_키가_노출되지_않는다() {
        when(dns.query(QUERY, RecordType.A)).thenReturn(listedAnswer("127.0.1.2"));

        CheckResult r = run();

        assertThat(r.evidence()).noneMatch(e -> e.contains("testkey123"));
        assertThat(r.guidance()).noneMatch(g -> g.contains("testkey123"));
    }
}
