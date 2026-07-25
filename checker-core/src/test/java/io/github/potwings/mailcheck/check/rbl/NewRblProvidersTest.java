package io.github.potwings.mailcheck.check.rbl;

import io.github.potwings.mailcheck.dns.DnsAnswer;
import io.github.potwings.mailcheck.dns.DnsRcode;
import io.github.potwings.mailcheck.dns.DnsRecordData;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

/** M5.5에서 추가된 IP RBL 프로바이더(PSBL, Mailspike, Hostkarma) 해석 검증. */
class NewRblProvidersTest {

    private static DnsAnswer answer(String... values) {
        return new DnsAnswer(DnsRcode.NOERROR,
                Arrays.stream(values).map(v -> new DnsRecordData(v, 60)).toList());
    }

    @Nested
    class Psbl {

        private final PsblProvider provider = new PsblProvider(true);

        @Test
        void 쿼리명은_psbl_존을_사용한다() {
            assertThat(provider.queryName("4.3.2.1")).isEqualTo("4.3.2.1.psbl.surriel.com");
        }

        @Test
        void NXDOMAIN은_미등재() {
            assertThat(provider.interpret(DnsAnswer.of(DnsRcode.NXDOMAIN)).type())
                    .isEqualTo(RblVerdict.Type.NOT_LISTED);
        }

        @Test
        void 등재_코드는_LISTED() {
            RblVerdict v = provider.interpret(answer("127.0.0.2"));

            assertThat(v.type()).isEqualTo(RblVerdict.Type.LISTED);
            assertThat(v.listings()).anyMatch(l -> l.contains("스팸트랩"));
        }

        @Test
        void 조회_실패는_ERROR() {
            assertThat(provider.interpret(DnsAnswer.of(DnsRcode.TIMEOUT)).type())
                    .isEqualTo(RblVerdict.Type.ERROR);
        }
    }

    @Nested
    class Mailspike {

        private final MailspikeProvider provider = new MailspikeProvider(true);

        @Test
        void 쿼리명은_mailspike_존을_사용한다() {
            assertThat(provider.queryName("4.3.2.1")).isEqualTo("4.3.2.1.bl.mailspike.net");
        }

        @Test
        void Z리스트와_평판_코드가_매핑된다() {
            RblVerdict v = provider.interpret(answer("127.0.0.2", "127.0.0.10"));

            assertThat(v.type()).isEqualTo(RblVerdict.Type.LISTED);
            assertThat(v.listings()).anyMatch(l -> l.contains("Z 리스트"));
            assertThat(v.listings()).anyMatch(l -> l.contains("L5"));
        }

        @Test
        void 알_수_없는_코드도_등재로_표시한다() {
            RblVerdict v = provider.interpret(answer("127.0.0.99"));

            assertThat(v.type()).isEqualTo(RblVerdict.Type.LISTED);
            assertThat(v.listings()).anyMatch(l -> l.contains("알 수 없는"));
        }

        @Test
        void NXDOMAIN은_미등재이고_조회_실패는_ERROR() {
            assertThat(provider.interpret(DnsAnswer.of(DnsRcode.NXDOMAIN)).type())
                    .isEqualTo(RblVerdict.Type.NOT_LISTED);
            assertThat(provider.interpret(DnsAnswer.of(DnsRcode.SERVFAIL)).type())
                    .isEqualTo(RblVerdict.Type.ERROR);
        }
    }

    @Nested
    class Hostkarma {

        private final HostkarmaProvider provider = new HostkarmaProvider(true);

        @Test
        void 쿼리명은_hostkarma_존을_사용한다() {
            assertThat(provider.queryName("4.3.2.1")).isEqualTo("4.3.2.1.hostkarma.junkemailfilter.com");
        }

        @Test
        void 블랙리스트와_브라운리스트는_LISTED() {
            RblVerdict black = provider.interpret(answer("127.0.0.2"));
            RblVerdict brown = provider.interpret(answer("127.0.0.4"));

            assertThat(black.type()).isEqualTo(RblVerdict.Type.LISTED);
            assertThat(black.listings()).anyMatch(l -> l.contains("블랙리스트"));
            assertThat(brown.type()).isEqualTo(RblVerdict.Type.LISTED);
            assertThat(brown.listings()).anyMatch(l -> l.contains("브라운리스트"));
        }

        @Test
        void 화이트_옐로_NOBL은_미등재로_처리한다() {
            assertThat(provider.interpret(answer("127.0.0.1")).type()).isEqualTo(RblVerdict.Type.NOT_LISTED);
            assertThat(provider.interpret(answer("127.0.0.3")).type()).isEqualTo(RblVerdict.Type.NOT_LISTED);
            assertThat(provider.interpret(answer("127.0.0.5")).type()).isEqualTo(RblVerdict.Type.NOT_LISTED);
        }

        @Test
        void NXDOMAIN은_미등재이고_조회_실패는_ERROR() {
            assertThat(provider.interpret(DnsAnswer.of(DnsRcode.NXDOMAIN)).type())
                    .isEqualTo(RblVerdict.Type.NOT_LISTED);
            assertThat(provider.interpret(DnsAnswer.of(DnsRcode.TIMEOUT)).type())
                    .isEqualTo(RblVerdict.Type.ERROR);
        }
    }
}
