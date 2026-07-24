package io.github.potwings.mailcheck.web.api;

import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class InputValidatorTest {

    @Test
    void 일반_도메인은_소문자로_정규화된다() {
        assertThat(InputValidator.normalizeDomain("Example.COM")).isEqualTo("example.com");
    }

    @Test
    void URL을_붙여넣어도_호스트만_추출한다() {
        assertThat(InputValidator.normalizeDomain("https://mail.example.com/path?q=1"))
                .isEqualTo("mail.example.com");
    }

    @Test
    void 한글_IDN은_punycode로_변환된다() {
        assertThat(InputValidator.normalizeDomain("한글도메인.kr")).startsWith("xn--");
    }

    @Test
    void 형식_오류는_400() {
        assertThatThrownBy(() -> InputValidator.normalizeDomain("not a domain"))
                .isInstanceOf(ResponseStatusException.class);
        assertThatThrownBy(() -> InputValidator.normalizeDomain("no-dot"))
                .isInstanceOf(ResponseStatusException.class);
        assertThatThrownBy(() -> InputValidator.normalizeDomain(""))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void IPv4는_통과하고_범위_초과는_400() {
        assertThat(InputValidator.normalizeIp("203.0.113.5")).isEqualTo("203.0.113.5");
        assertThatThrownBy(() -> InputValidator.normalizeIp("300.1.1.1"))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void IPv6_리터럴은_통과한다() {
        assertThat(InputValidator.normalizeIp("2001:db8::1")).isNotNull();
    }

    @Test
    void 빈_IP는_null() {
        assertThat(InputValidator.normalizeIp(null)).isNull();
        assertThat(InputValidator.normalizeIp("  ")).isNull();
    }
}
