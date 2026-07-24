package io.github.potwings.mailcheck.check.dmarc;

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

class DmarcCheckTest {

    private DnsQueryService dns;
    private DmarcCheck check;

    @BeforeEach
    void setUp() {
        dns = mock(DnsQueryService.class);
        check = new DmarcCheck(dns, new OrgDomainResolver());
    }

    private static DnsAnswer txt(String... records) {
        return new DnsAnswer(DnsRcode.NOERROR,
                Arrays.stream(records).map(r -> new DnsRecordData(r, 300)).toList());
    }

    private static final DnsAnswer EMPTY = DnsAnswer.of(DnsRcode.NOERROR);

    private CheckResult run(String domain) {
        return check.run(new CheckContext(domain, null, null));
    }

    @Test
    void 레코드가_없으면_FAIL() {
        when(dns.query("_dmarc.example.com", RecordType.TXT)).thenReturn(EMPTY);

        assertThat(run("example.com").status()).isEqualTo(CheckStatus.FAIL);
    }

    @Test
    void p_none은_WARN() {
        when(dns.query("_dmarc.example.com", RecordType.TXT))
                .thenReturn(txt("v=DMARC1; p=none; rua=mailto:r@example.com"));

        CheckResult r = run("example.com");

        assertThat(r.status()).isEqualTo(CheckStatus.WARN);
        assertThat(r.evidence()).anyMatch(e -> e.contains("none"));
    }

    @Test
    void p_reject_전체_태그는_PASS() {
        when(dns.query("_dmarc.example.com", RecordType.TXT))
                .thenReturn(txt("v=DMARC1; p=reject; rua=mailto:r@example.com; adkim=s; aspf=s"));

        assertThat(run("example.com").status()).isEqualTo(CheckStatus.PASS);
    }

    @Test
    void 서브도메인은_조직_도메인으로_폴백한다() {
        when(dns.query("_dmarc.mail.example.com", RecordType.TXT)).thenReturn(EMPTY);
        when(dns.query("_dmarc.example.com", RecordType.TXT))
                .thenReturn(txt("v=DMARC1; p=reject; rua=mailto:r@example.com"));

        CheckResult r = run("mail.example.com");

        assertThat(r.status()).isEqualTo(CheckStatus.PASS);
        assertThat(r.evidence()).anyMatch(e -> e.contains("조직 도메인"));
    }

    @Test
    void 폴백_시_sp가_있으면_서브도메인에는_sp가_적용된다() {
        when(dns.query("_dmarc.mail.example.com", RecordType.TXT)).thenReturn(EMPTY);
        when(dns.query("_dmarc.example.com", RecordType.TXT))
                .thenReturn(txt("v=DMARC1; p=reject; sp=none; rua=mailto:r@example.com"));

        CheckResult r = run("mail.example.com");

        assertThat(r.status()).isEqualTo(CheckStatus.WARN);
        assertThat(r.evidence()).anyMatch(e -> e.contains("sp=none"));
    }

    @Test
    void 중복_레코드는_FAIL() {
        when(dns.query("_dmarc.example.com", RecordType.TXT))
                .thenReturn(txt("v=DMARC1; p=reject", "v=DMARC1; p=none"));

        assertThat(run("example.com").status()).isEqualTo(CheckStatus.FAIL);
    }

    @Test
    void p_태그_누락은_FAIL() {
        when(dns.query("_dmarc.example.com", RecordType.TXT))
                .thenReturn(txt("v=DMARC1; rua=mailto:r@example.com"));

        assertThat(run("example.com").status()).isEqualTo(CheckStatus.FAIL);
    }

    @Test
    void pct_100_미만은_WARN() {
        when(dns.query("_dmarc.example.com", RecordType.TXT))
                .thenReturn(txt("v=DMARC1; p=reject; pct=50; rua=mailto:r@example.com"));

        CheckResult r = run("example.com");

        assertThat(r.status()).isEqualTo(CheckStatus.WARN);
        assertThat(r.evidence()).anyMatch(e -> e.contains("pct=50"));
    }

    @Test
    void rua_누락은_WARN() {
        when(dns.query("_dmarc.example.com", RecordType.TXT)).thenReturn(txt("v=DMARC1; p=reject"));

        assertThat(run("example.com").status()).isEqualTo(CheckStatus.WARN);
    }
}
