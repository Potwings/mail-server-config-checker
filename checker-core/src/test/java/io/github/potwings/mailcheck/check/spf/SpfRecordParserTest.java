package io.github.potwings.mailcheck.check.spf;

import io.github.potwings.mailcheck.check.spf.SpfRecordParser.ParseResult;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SpfRecordParserTest {

    private final SpfRecordParser parser = new SpfRecordParser();

    @Test
    void 정상_레코드는_메커니즘과_qualifier를_파싱한다() {
        ParseResult r = parser.parse("v=spf1 ip4:203.0.113.0/24 include:_spf.example.com a mx -all");

        assertThat(r.errors()).isEmpty();
        assertThat(r.terms()).hasSize(5);
        assertThat(r.terms().get(0).name()).isEqualTo("ip4");
        assertThat(r.terms().get(0).value()).isEqualTo("203.0.113.0/24");
        assertThat(r.terms().get(1).name()).isEqualTo("include");
        assertThat(r.terms().get(4).name()).isEqualTo("all");
        assertThat(r.terms().get(4).qualifier()).isEqualTo('-');
    }

    @Test
    void v_spf1로_시작하지_않으면_오류() {
        ParseResult r = parser.parse("spf1 ip4:1.2.3.4 -all");

        assertThat(r.errors()).isNotEmpty();
    }

    @Test
    void 알_수_없는_메커니즘은_오류() {
        ParseResult r = parser.parse("v=spf1 foobar:x -all");

        assertThat(r.errors()).anyMatch(e -> e.contains("foobar"));
    }

    @Test
    void ip4_옥텟_범위_초과는_오류() {
        ParseResult r = parser.parse("v=spf1 ip4:999.0.0.1 -all");

        assertThat(r.errors()).anyMatch(e -> e.contains("ip4"));
    }

    @Test
    void ip4_CIDR_범위_초과는_오류() {
        ParseResult r = parser.parse("v=spf1 ip4:203.0.113.0/33 -all");

        assertThat(r.errors()).anyMatch(e -> e.contains("ip4"));
    }

    @Test
    void ip6_리터럴은_통과한다() {
        ParseResult r = parser.parse("v=spf1 ip6:2001:db8::1/64 -all");

        assertThat(r.errors()).isEmpty();
    }

    @Test
    void redirect는_modifier로_파싱된다() {
        ParseResult r = parser.parse("v=spf1 redirect=_spf.example.com");

        assertThat(r.errors()).isEmpty();
        assertThat(r.terms()).hasSize(1);
        assertThat(r.terms().get(0).modifier()).isTrue();
        assertThat(r.terms().get(0).name()).isEqualTo("redirect");
        assertThat(r.terms().get(0).value()).isEqualTo("_spf.example.com");
    }

    @Test
    void 메커니즘을_modifier_문법으로_쓰면_경고() {
        ParseResult r = parser.parse("v=spf1 ip4=203.0.113.5 -all");

        assertThat(r.errors()).isEmpty();
        assertThat(r.warnings()).anyMatch(w -> w.contains("ip4"));
    }

    @Test
    void isSpfRecord는_v_spf1_레코드만_인식한다() {
        assertThat(SpfRecordParser.isSpfRecord("v=spf1 -all")).isTrue();
        assertThat(SpfRecordParser.isSpfRecord("v=spf1")).isTrue();
        assertThat(SpfRecordParser.isSpfRecord("v=spf10 -all")).isFalse();
        assertThat(SpfRecordParser.isSpfRecord("v=DMARC1; p=none")).isFalse();
        assertThat(SpfRecordParser.isSpfRecord("google-site-verification=abc")).isFalse();
    }
}
