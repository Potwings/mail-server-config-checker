package io.github.potwings.mailcheck.check.rbl;

import io.github.potwings.mailcheck.dns.DnsAnswer;
import io.github.potwings.mailcheck.dns.DnsRcode;
import io.github.potwings.mailcheck.dns.DnsRecordData;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

class SpamhausZenDqsProviderTest {

    private final SpamhausZenDqsProvider provider = new SpamhausZenDqsProvider("testkey123");

    private static DnsAnswer answer(String... values) {
        return new DnsAnswer(DnsRcode.NOERROR,
                Arrays.stream(values).map(v -> new DnsRecordData(v, 60)).toList());
    }

    @Test
    void DQS_키가_쿼리명에_포함된다() {
        assertThat(provider.queryName("4.3.2.1"))
                .isEqualTo("4.3.2.1.testkey123.zen.dq.spamhaus.net");
    }

    @Test
    void 키가_없으면_비활성화() {
        assertThat(new SpamhausZenDqsProvider("").enabled()).isFalse();
        assertThat(new SpamhausZenDqsProvider(null).enabled()).isFalse();
        assertThat(provider.enabled()).isTrue();
    }

    @Test
    void NXDOMAIN은_미등재() {
        assertThat(provider.interpret(DnsAnswer.of(DnsRcode.NXDOMAIN)).type())
                .isEqualTo(RblVerdict.Type.NOT_LISTED);
    }

    @Test
    void 등재_코드는_리스트명으로_매핑된다() {
        RblVerdict v = provider.interpret(answer("127.0.0.2", "127.0.0.10"));

        assertThat(v.type()).isEqualTo(RblVerdict.Type.LISTED);
        assertThat(v.listings()).anyMatch(l -> l.contains("SBL"));
        assertThat(v.listings()).anyMatch(l -> l.contains("PBL"));
    }

    @Test
    void 오류_코드_127_255_255_x는_미등재가_아니라_ERROR() {
        RblVerdict v = provider.interpret(answer("127.255.255.254"));

        assertThat(v.type()).isEqualTo(RblVerdict.Type.ERROR);
        assertThat(v.detail()).contains("127.255.255.254");
    }

    @Test
    void 조회_실패는_ERROR() {
        assertThat(provider.interpret(DnsAnswer.of(DnsRcode.TIMEOUT)).type())
                .isEqualTo(RblVerdict.Type.ERROR);
    }
}
