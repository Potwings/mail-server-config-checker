package io.github.potwings.mailcheck.check.propagation;

import io.github.potwings.mailcheck.api.CheckContext;
import io.github.potwings.mailcheck.api.CheckResult;
import io.github.potwings.mailcheck.api.CheckStatus;
import io.github.potwings.mailcheck.check.dmarc.OrgDomainResolver;
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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class DnsPropagationCheckTest {

    private static final String DOMAIN = "example.com";
    private static final String AUTH_IP = "198.51.100.53";

    private DnsQueryService dns;
    private DnsPropagationCheck check;

    @BeforeEach
    void setUp() {
        dns = mock(DnsQueryService.class);
        List<ResolverEndpoint> resolvers = List.of(
                new ResolverEndpoint("Google", "8.8.8.8"),
                new ResolverEndpoint("KT", "168.126.63.1"));
        check = new DnsPropagationCheck(dns, resolvers, new OrgDomainResolver());

        when(dns.query(DOMAIN, RecordType.NS)).thenReturn(answer("ns1.example.com"));
        when(dns.query("ns1.example.com", RecordType.A)).thenReturn(answer(AUTH_IP));
        // default: every via-query answers empty
        when(dns.queryVia(anyString(), anyString(), any())).thenReturn(DnsAnswer.of(DnsRcode.NOERROR));
    }

    private static DnsAnswer answer(String... values) {
        return new DnsAnswer(DnsRcode.NOERROR,
                Arrays.stream(values).map(v -> new DnsRecordData(v, 300)).toList());
    }

    private void stubEverywhere(String qname, RecordType type, DnsAnswer ans) {
        when(dns.queryVia(AUTH_IP, qname, type)).thenReturn(ans);
        when(dns.queryVia("8.8.8.8", qname, type)).thenReturn(ans);
        when(dns.queryVia("168.126.63.1", qname, type)).thenReturn(ans);
    }

    private CheckResult run() {
        return check.run(new CheckContext(DOMAIN, null, null));
    }

    @Test
    void 모든_리졸버가_기준값과_일치하면_PASS() {
        stubEverywhere(DOMAIN, RecordType.A, answer("203.0.113.10"));
        stubEverywhere(DOMAIN, RecordType.MX, answer("10 mx1.example.com"));
        stubEverywhere(DOMAIN, RecordType.TXT, answer("v=spf1 -all", "some-other-txt"));
        stubEverywhere("_dmarc." + DOMAIN, RecordType.TXT, answer("v=DMARC1; p=reject"));

        CheckResult r = run();

        assertThat(r.status()).isEqualTo(CheckStatus.PASS);
        assertThat(r.evidence()).anyMatch(e -> e.contains("SPF: 2/2"));
    }

    @Test
    void 일부_리졸버가_다른_값을_주면_WARN과_불일치_리졸버_표시() {
        stubEverywhere(DOMAIN, RecordType.A, answer("203.0.113.10"));
        stubEverywhere(DOMAIN, RecordType.MX, answer("10 mx1.example.com"));
        stubEverywhere(DOMAIN, RecordType.TXT, answer("v=spf1 -all"));
        stubEverywhere("_dmarc." + DOMAIN, RecordType.TXT, answer("v=DMARC1; p=reject"));
        // KT still serves the old MX from cache
        when(dns.queryVia("168.126.63.1", DOMAIN, RecordType.MX)).thenReturn(answer("10 old-mx.example.com"));

        CheckResult r = run();

        assertThat(r.status()).isEqualTo(CheckStatus.WARN);
        assertThat(r.evidence()).anyMatch(e -> e.contains("MX: 1/2") && e.contains("KT"));
    }

    @Test
    void 리졸버_무응답은_불일치가_아니라_응답_없음으로_구분() {
        stubEverywhere(DOMAIN, RecordType.A, answer("203.0.113.10"));
        stubEverywhere(DOMAIN, RecordType.MX, answer("10 mx1.example.com"));
        stubEverywhere(DOMAIN, RecordType.TXT, answer("v=spf1 -all"));
        stubEverywhere("_dmarc." + DOMAIN, RecordType.TXT, answer("v=DMARC1; p=reject"));
        when(dns.queryVia("168.126.63.1", DOMAIN, RecordType.A)).thenReturn(DnsAnswer.of(DnsRcode.TIMEOUT));

        CheckResult r = run();

        assertThat(r.status()).isEqualTo(CheckStatus.PASS);
        assertThat(r.evidence()).anyMatch(e -> e.contains("A: 1/1") && e.contains("응답 없음: KT"));
    }

    @Test
    void 권한_NS를_찾지_못하면_ERROR() {
        when(dns.query(DOMAIN, RecordType.NS)).thenReturn(DnsAnswer.of(DnsRcode.NOERROR));

        assertThat(run().status()).isEqualTo(CheckStatus.ERROR);
    }
}
