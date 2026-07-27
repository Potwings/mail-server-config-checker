package io.github.potwings.mailcheck.mail.util;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class DomainsTest {

    @Test
    void 일반_도메인은_소문자로_정규화() {
        assertThat(Domains.normalize("Example.COM")).isEqualTo("example.com");
    }

    @Test
    void 말미_점은_제거() {
        assertThat(Domains.normalize("example.com.")).isEqualTo("example.com");
    }

    @Test
    void 한글_IDN은_punycode로_변환() {
        assertThat(Domains.normalize("한글도메인.kr")).startsWith("xn--");
    }

    @Test
    void 형식_오류는_null() {
        assertThat(Domains.normalize("not a domain")).isNull();
        assertThat(Domains.normalize("no-dot")).isNull();
        assertThat(Domains.normalize("")).isNull();
        assertThat(Domains.normalize(null)).isNull();
        assertThat(Domains.normalize("[203.0.113.5]")).isNull();
    }
}
