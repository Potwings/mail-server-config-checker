package io.github.potwings.mailcheck.check.rbl;

import io.github.potwings.mailcheck.dns.DnsAnswer;
import io.github.potwings.mailcheck.dns.DnsRcode;
import io.github.potwings.mailcheck.dns.DnsRecordData;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

class SpamhausDblProviderTest {

    private final SpamhausDblProvider provider = new SpamhausDblProvider("testkey123");

    private static DnsAnswer answer(String... values) {
        return new DnsAnswer(DnsRcode.NOERROR,
                Arrays.stream(values).map(v -> new DnsRecordData(v, 60)).toList());
    }

    @Test
    void DQS_키가_쿼리명에_포함된다() {
        assertThat(provider.queryName("example.com"))
                .isEqualTo("example.com.testkey123.dbl.dq.spamhaus.net");
    }

    @Test
    void 키가_없으면_비활성화() {
        assertThat(new SpamhausDblProvider("").enabled()).isFalse();
        assertThat(new SpamhausDblProvider(null).enabled()).isFalse();
        assertThat(provider.enabled()).isTrue();
    }

    @Test
    void NXDOMAIN은_미등재() {
        assertThat(provider.interpret(DnsAnswer.of(DnsRcode.NXDOMAIN)).type())
                .isEqualTo(RblVerdict.Type.NOT_LISTED);
    }

    @Test
    void 등재_코드는_유형으로_매핑된다() {
        RblVerdict v = provider.interpret(answer("127.0.1.2", "127.0.1.104"));

        assertThat(v.type()).isEqualTo(RblVerdict.Type.LISTED);
        assertThat(v.listings()).anyMatch(l -> l.contains("스팸 도메인"));
        assertThat(v.listings()).anyMatch(l -> l.contains("악용된 정상 도메인 (피싱)"));
    }

    @Test
    void DQS_오류_코드_127_255_255_x는_미등재가_아니라_ERROR() {
        RblVerdict v = provider.interpret(answer("127.255.255.254"));

        assertThat(v.type()).isEqualTo(RblVerdict.Type.ERROR);
        assertThat(v.detail()).contains("127.255.255.254");
    }

    @Test
    void IP_쿼리_금지_코드_127_0_1_255는_ERROR() {
        assertThat(provider.interpret(answer("127.0.1.255")).type())
                .isEqualTo(RblVerdict.Type.ERROR);
    }

    @Test
    void 조회_실패는_ERROR() {
        assertThat(provider.interpret(DnsAnswer.of(DnsRcode.SERVFAIL)).type())
                .isEqualTo(RblVerdict.Type.ERROR);
    }
}
