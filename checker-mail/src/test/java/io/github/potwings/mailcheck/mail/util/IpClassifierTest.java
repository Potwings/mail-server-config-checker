package io.github.potwings.mailcheck.mail.util;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class IpClassifierTest {

    @Test
    void 공인_IP는_진단_가능() {
        assertThat(IpClassifier.isNonPublic("203.0.113.50")).isFalse();
        assertThat(IpClassifier.isNonPublic("2001:db8::1")).isFalse();
    }

    @Test
    void RFC1918_사설_대역은_비공인() {
        assertThat(IpClassifier.isNonPublic("10.0.0.1")).isTrue();
        assertThat(IpClassifier.isNonPublic("172.30.1.254")).isTrue();
        assertThat(IpClassifier.isNonPublic("192.168.0.10")).isTrue();
    }

    @Test
    void 루프백_링크로컬_any는_비공인() {
        assertThat(IpClassifier.isNonPublic("127.0.0.1")).isTrue();
        assertThat(IpClassifier.isNonPublic("169.254.1.1")).isTrue();
        assertThat(IpClassifier.isNonPublic("0.0.0.0")).isTrue();
        assertThat(IpClassifier.isNonPublic("::1")).isTrue();
        assertThat(IpClassifier.isNonPublic("fe80::1")).isTrue();
    }

    @Test
    void IPv6_ULA는_비공인() {
        assertThat(IpClassifier.isNonPublic("fc00::1")).isTrue();
        assertThat(IpClassifier.isNonPublic("fd12:3456:789a::1")).isTrue();
    }

    @Test
    void 파싱_불가는_fail_safe로_비공인() {
        assertThat(IpClassifier.isNonPublic(null)).isTrue();
        assertThat(IpClassifier.isNonPublic("")).isTrue();
        assertThat(IpClassifier.isNonPublic("mx.example.com")).isTrue();
        assertThat(IpClassifier.isNonPublic("300.1.1.1")).isTrue();
    }
}
