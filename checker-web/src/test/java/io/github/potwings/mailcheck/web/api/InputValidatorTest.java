package io.github.potwings.mailcheck.web.api;

import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

import java.util.stream.Collectors;
import java.util.stream.IntStream;

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
        assertThat(InputValidator.normalizeIps("203.0.113.5")).containsExactly("203.0.113.5");
        assertThatThrownBy(() -> InputValidator.normalizeIps("300.1.1.1"))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void IPv6_리터럴은_통과한다() {
        assertThat(InputValidator.normalizeIps("2001:db8::1")).hasSize(1);
    }

    @Test
    void 빈_IP는_빈_리스트() {
        assertThat(InputValidator.normalizeIps(null)).isEmpty();
        assertThat(InputValidator.normalizeIps("  ")).isEmpty();
    }

    @Test
    void 쉼표로_구분한_다중_IP는_공백을_제거하고_모두_반환한다() {
        assertThat(InputValidator.normalizeIps("203.0.113.5, 203.0.113.6 ,203.0.113.7"))
                .containsExactly("203.0.113.5", "203.0.113.6", "203.0.113.7");
    }

    @Test
    void 중복_IP와_빈_항목은_제거된다() {
        assertThat(InputValidator.normalizeIps("203.0.113.5,,203.0.113.5,"))
                .containsExactly("203.0.113.5");
    }

    @Test
    void 다중_IP_중_하나라도_형식이_틀리면_400() {
        assertThatThrownBy(() -> InputValidator.normalizeIps("203.0.113.5,abc"))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void IP_개수가_상한_이내면_모두_허용된다() {
        String ips = IntStream.rangeClosed(1, InputValidator.MAX_TARGET_IPS)
                .mapToObj(i -> "10.0.0." + i)
                .collect(Collectors.joining(","));

        assertThat(InputValidator.normalizeIps(ips)).hasSize(InputValidator.MAX_TARGET_IPS);
    }

    @Test
    void IP_개수_상한을_초과하면_400() {
        String ips = IntStream.rangeClosed(1, InputValidator.MAX_TARGET_IPS + 1)
                .mapToObj(i -> "10.0.0." + i)
                .collect(Collectors.joining(","));

        assertThatThrownBy(() -> InputValidator.normalizeIps(ips))
                .isInstanceOf(ResponseStatusException.class);
    }
}
