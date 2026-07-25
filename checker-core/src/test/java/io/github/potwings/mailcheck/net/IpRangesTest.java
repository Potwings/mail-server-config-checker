package io.github.potwings.mailcheck.net;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class IpRangesTest {

    @Test
    void 사설_예약_대역은_사유를_반환한다() {
        assertThat(IpRanges.nonRoutableReason("10.0.0.1")).contains("사설");
        assertThat(IpRanges.nonRoutableReason("172.16.0.1")).contains("사설");
        assertThat(IpRanges.nonRoutableReason("192.168.1.1")).contains("사설");
        assertThat(IpRanges.nonRoutableReason("100.64.0.1")).contains("CGNAT");
        assertThat(IpRanges.nonRoutableReason("127.0.0.1")).contains("루프백");
        assertThat(IpRanges.nonRoutableReason("169.254.1.1")).contains("링크로컬");
        assertThat(IpRanges.nonRoutableReason("0.0.0.0")).contains("미지정");
        assertThat(IpRanges.nonRoutableReason("224.0.0.1")).contains("멀티캐스트");
        assertThat(IpRanges.nonRoutableReason("240.0.0.1")).contains("예약");
        assertThat(IpRanges.nonRoutableReason("::1")).contains("루프백");
        assertThat(IpRanges.nonRoutableReason("fe80::1")).contains("링크로컬");
        assertThat(IpRanges.nonRoutableReason("fd12:3456::1")).contains("ULA");
    }

    @Test
    void 공인_IP는_null을_반환한다() {
        assertThat(IpRanges.nonRoutableReason("8.8.8.8")).isNull();
        assertThat(IpRanges.nonRoutableReason("2606:4700::1111")).isNull();
        // 문서화 대역(TEST-NET)은 예제/테스트 관례상 의도적으로 허용
        assertThat(IpRanges.nonRoutableReason("203.0.113.5")).isNull();
        assertThat(IpRanges.nonRoutableReason("2001:db8::1")).isNull();
    }

    @Test
    void IP_리터럴이_아니면_null을_반환한다() {
        assertThat(IpRanges.nonRoutableReason("mail.example.com")).isNull();
    }
}
