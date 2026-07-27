package io.github.potwings.mailcheck.check.spf;

import io.github.potwings.mailcheck.check.spf.SpfEvaluator.Evaluation;
import io.github.potwings.mailcheck.check.spf.SpfEvaluator.Verdict;
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

class SpfEvaluatorTest {

    private static final String DOMAIN = "example.com";

    private DnsQueryService dns;
    private SpfEvaluator evaluator;
    private final SpfRecordParser parser = new SpfRecordParser();

    @BeforeEach
    void setUp() {
        dns = mock(DnsQueryService.class);
        evaluator = new SpfEvaluator(dns);
    }

    private static DnsAnswer answer(String... records) {
        return new DnsAnswer(DnsRcode.NOERROR,
                Arrays.stream(records).map(r -> new DnsRecordData(r, 300)).toList());
    }

    private Evaluation eval(String ip, String record) {
        return evaluator.evaluate(ip, DOMAIN, parser.parse(record).terms());
    }

    @Test
    void ip4_일치는_pass() {
        Evaluation ev = eval("203.0.113.5", "v=spf1 ip4:203.0.113.5 -all");

        assertThat(ev.verdict()).isEqualTo(Verdict.PASS);
        assertThat(ev.matched()).isEqualTo("ip4:203.0.113.5");
    }

    @Test
    void ip4_CIDR_범위_매칭() {
        assertThat(eval("203.0.113.200", "v=spf1 ip4:203.0.113.0/24 -all").verdict())
                .isEqualTo(Verdict.PASS);
        assertThat(eval("203.0.114.1", "v=spf1 ip4:203.0.113.0/24 -all").verdict())
                .isEqualTo(Verdict.FAIL);
    }

    @Test
    void 미허용_IP는_minus_all이면_fail() {
        Evaluation ev = eval("198.51.100.9", "v=spf1 ip4:203.0.113.5 -all");

        assertThat(ev.verdict()).isEqualTo(Verdict.FAIL);
        assertThat(ev.matched()).isEqualTo("-all");
    }

    @Test
    void 미허용_IP는_tilde_all이면_softfail() {
        assertThat(eval("198.51.100.9", "v=spf1 ip4:203.0.113.5 ~all").verdict())
                .isEqualTo(Verdict.SOFTFAIL);
    }

    @Test
    void all_없으면_neutral() {
        assertThat(eval("198.51.100.9", "v=spf1 ip4:203.0.113.5").verdict())
                .isEqualTo(Verdict.NEUTRAL);
    }

    @Test
    void ip6_매칭() {
        assertThat(eval("2001:db8::1", "v=spf1 ip6:2001:db8::/32 -all").verdict())
                .isEqualTo(Verdict.PASS);
        assertThat(eval("2001:db9::1", "v=spf1 ip6:2001:db8::/32 -all").verdict())
                .isEqualTo(Verdict.FAIL);
    }

    @Test
    void ip4_메커니즘은_IPv6_발신_IP와_매칭되지_않음() {
        assertThat(eval("2001:db8::1", "v=spf1 ip4:203.0.113.5 -all").verdict())
                .isEqualTo(Verdict.FAIL);
    }

    @Test
    void a_메커니즘은_현재_도메인의_A_레코드와_비교() {
        when(dns.query(DOMAIN, RecordType.A)).thenReturn(answer("203.0.113.5"));

        assertThat(eval("203.0.113.5", "v=spf1 a -all").verdict()).isEqualTo(Verdict.PASS);
    }

    @Test
    void a_메커니즘_도메인_및_CIDR_지정() {
        when(dns.query("mail.example.net", RecordType.A)).thenReturn(answer("198.51.100.1"));

        assertThat(eval("198.51.100.77", "v=spf1 a:mail.example.net/24 -all").verdict())
                .isEqualTo(Verdict.PASS);
    }

    @Test
    void mx_메커니즘은_MX_호스트의_A_레코드와_비교() {
        when(dns.query(DOMAIN, RecordType.MX)).thenReturn(answer("10 mx1.example.com", "20 mx2.example.com"));
        when(dns.query("mx1.example.com", RecordType.A)).thenReturn(answer("192.0.2.1"));
        when(dns.query("mx2.example.com", RecordType.A)).thenReturn(answer("192.0.2.2"));

        assertThat(eval("192.0.2.2", "v=spf1 mx -all").verdict()).isEqualTo(Verdict.PASS);
        assertThat(eval("192.0.2.9", "v=spf1 mx -all").verdict()).isEqualTo(Verdict.FAIL);
    }

    @Test
    void include_재귀_pass면_매칭() {
        when(dns.query("_spf.example.net", RecordType.TXT))
                .thenReturn(answer("v=spf1 ip4:198.51.100.0/24 -all"));

        Evaluation ev = eval("198.51.100.9", "v=spf1 include:_spf.example.net -all");

        assertThat(ev.verdict()).isEqualTo(Verdict.PASS);
        assertThat(ev.matched()).isEqualTo("include:_spf.example.net");
    }

    @Test
    void include_재귀가_fail이어도_다음_메커니즘으로_계속() {
        when(dns.query("_spf.example.net", RecordType.TXT))
                .thenReturn(answer("v=spf1 ip4:198.51.100.0/24 -all"));

        Evaluation ev = eval("203.0.113.5", "v=spf1 include:_spf.example.net ip4:203.0.113.5 -all");

        assertThat(ev.verdict()).isEqualTo(Verdict.PASS);
        assertThat(ev.matched()).isEqualTo("ip4:203.0.113.5");
    }

    @Test
    void include_대상에_SPF가_없으면_permerror() {
        when(dns.query("nospf.example.net", RecordType.TXT)).thenReturn(answer("plain txt"));

        assertThat(eval("203.0.113.5", "v=spf1 include:nospf.example.net -all").verdict())
                .isEqualTo(Verdict.PERMERROR);
    }

    @Test
    void redirect는_대상_도메인의_정책을_따름() {
        when(dns.query("policy.example.net", RecordType.TXT))
                .thenReturn(answer("v=spf1 ip4:203.0.113.0/24 -all"));

        assertThat(eval("203.0.113.5", "v=spf1 redirect=policy.example.net").verdict())
                .isEqualTo(Verdict.PASS);
        assertThat(eval("198.51.100.9", "v=spf1 redirect=policy.example.net").verdict())
                .isEqualTo(Verdict.FAIL);
    }

    @Test
    void exists_매크로_i_확장() {
        when(dns.query("5.113.0.203.check.example.net", RecordType.A)).thenReturn(answer("127.0.0.2"));

        // %{ir} = IP 라벨 역순 → 5.113.0.203
        assertThat(eval("203.0.113.5", "v=spf1 exists:%{ir}.check.example.net -all").verdict())
                .isEqualTo(Verdict.PASS);
    }

    @Test
    void 세션_의존_매크로_메커니즘은_평가_제외하고_계속() {
        Evaluation ev = eval("203.0.113.5", "v=spf1 exists:%{h}.helo.example.net ip4:203.0.113.5 -all");

        assertThat(ev.verdict()).isEqualTo(Verdict.PASS);
        assertThat(ev.notes()).anyMatch(n -> n.contains("%{h}"));
    }

    // ---- 실세션(SmtpSession) 매크로 확장 ----

    private Evaluation evalWithSession(String ip, String record, SpfEvaluator.SmtpSession session) {
        return evaluator.evaluate(ip, DOMAIN, parser.parse(record).terms(), session);
    }

    @Test
    void 세션이_있으면_h_매크로가_실제_HELO로_확장되어_exists_매칭() {
        when(dns.query("mail.sender.example.helo.example.net", RecordType.A))
                .thenReturn(answer("127.0.0.2"));

        Evaluation ev = evalWithSession("203.0.113.5",
                "v=spf1 exists:%{h}.helo.example.net -all",
                new SpfEvaluator.SmtpSession("user@sender.example", "mail.sender.example"));

        assertThat(ev.verdict()).isEqualTo(Verdict.PASS);
        assertThat(ev.notes()).noneMatch(n -> n.contains("%{h}"));
    }

    @Test
    void 세션이_있으면_s_l_o_매크로가_실제_발신자_값으로_확장() {
        // %{l} = user, %{o} = sender.example, %{s} = user@sender.example(@는 구분자 아님 → 한 라벨)
        when(dns.query("user.sender.example.check.example.net", RecordType.A))
                .thenReturn(answer("127.0.0.2"));

        Evaluation ev = evalWithSession("203.0.113.5",
                "v=spf1 exists:%{l}.%{o}.check.example.net -all",
                new SpfEvaluator.SmtpSession("user@sender.example", "mail.sender.example"));

        assertThat(ev.verdict()).isEqualTo(Verdict.PASS);
    }

    @Test
    void 세션이_있어도_HELO가_없으면_h_매크로는_기존대로_스킵() {
        Evaluation ev = evalWithSession("203.0.113.5",
                "v=spf1 exists:%{h}.helo.example.net ip4:203.0.113.5 -all",
                new SpfEvaluator.SmtpSession("user@sender.example", null));

        assertThat(ev.verdict()).isEqualTo(Verdict.PASS);
        assertThat(ev.notes()).anyMatch(n -> n.contains("%{h}"));
    }

    @Test
    void 세션이_없으면_s_매크로는_합성_postmaster_발신자로_확장() {
        when(dns.query("postmaster." + DOMAIN + ".check.example.net", RecordType.A))
                .thenReturn(answer("127.0.0.2"));

        Evaluation ev = eval("203.0.113.5", "v=spf1 exists:%{l}.%{o}.check.example.net -all");

        assertThat(ev.verdict()).isEqualTo(Verdict.PASS);
    }

    @Test
    void ptr_메커니즘은_FCrDNS_확인_후_도메인_접미사_매칭() {
        when(dns.query("203.0.113.5", RecordType.PTR)).thenReturn(answer("mail.example.com"));
        when(dns.query("mail.example.com", RecordType.A)).thenReturn(answer("203.0.113.5"));

        assertThat(eval("203.0.113.5", "v=spf1 ptr -all").verdict()).isEqualTo(Verdict.PASS);
    }

    @Test
    void lookup_10회_초과는_permerror() {
        for (int i = 1; i <= 11; i++) {
            when(dns.query("h" + i + ".example.com", RecordType.A)).thenReturn(answer("192.0.2." + i));
        }
        StringBuilder record = new StringBuilder("v=spf1");
        for (int i = 1; i <= 11; i++) {
            record.append(" a:h").append(i).append(".example.com");
        }
        record.append(" -all");

        assertThat(eval("203.0.113.5", record.toString()).verdict()).isEqualTo(Verdict.PERMERROR);
    }

    @Test
    void include_순환_참조는_permerror() {
        when(dns.query("loop.example.net", RecordType.TXT))
                .thenReturn(answer("v=spf1 include:" + DOMAIN + " -all"));
        when(dns.query(DOMAIN, RecordType.TXT))
                .thenReturn(answer("v=spf1 include:loop.example.net -all"));

        assertThat(eval("203.0.113.5", "v=spf1 include:loop.example.net -all").verdict())
                .isEqualTo(Verdict.PERMERROR);
    }

    @Test
    void DNS_조회_실패는_temperror() {
        when(dns.query(DOMAIN, RecordType.A)).thenReturn(DnsAnswer.of(DnsRcode.TIMEOUT));

        assertThat(eval("203.0.113.5", "v=spf1 a -all").verdict()).isEqualTo(Verdict.TEMPERROR);
    }
}
