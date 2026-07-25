package io.github.potwings.mailcheck.engine;

import io.github.potwings.mailcheck.dns.DnsAnswer;
import io.github.potwings.mailcheck.dns.DnsQueryService;
import io.github.potwings.mailcheck.dns.DnsRcode;
import io.github.potwings.mailcheck.dns.DnsRecordData;
import io.github.potwings.mailcheck.dns.RecordType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class TargetIpResolverTest {

    private static final String DOMAIN = "example.com";
    private static final DnsAnswer EMPTY = DnsAnswer.of(DnsRcode.NOERROR);

    private DnsQueryService dns;
    private TargetIpResolver resolver;

    @BeforeEach
    void setUp() {
        dns = mock(DnsQueryService.class);
        when(dns.query(anyString(), any(RecordType.class))).thenReturn(EMPTY);
        resolver = new TargetIpResolver(dns);
    }

    private static DnsAnswer answer(String... values) {
        return new DnsAnswer(DnsRcode.NOERROR,
                Arrays.stream(values).map(v -> new DnsRecordData(v, 300)).toList());
    }

    @Test
    void 사용자_입력_IP가_MX보다_우선한다() {
        when(dns.query(DOMAIN, RecordType.MX)).thenReturn(answer("10 mx1.example.com"));

        Optional<TargetIpResolver.TargetIps> result = resolver.resolve(DOMAIN, List.of("198.51.100.7"));

        assertThat(result).isPresent();
        assertThat(result.get().ips()).containsExactly("198.51.100.7");
        assertThat(result.get().source()).isEqualTo("사용자 입력");
        verify(dns, never()).query(anyString(), any(RecordType.class));
    }

    @Test
    void 사용자_입력_IP가_여러개면_순서를_유지한_채_모두_사용한다() {
        Optional<TargetIpResolver.TargetIps> result =
                resolver.resolve(DOMAIN, List.of("198.51.100.7", "198.51.100.8", "203.0.113.1"));

        assertThat(result).isPresent();
        assertThat(result.get().ips()).containsExactly("198.51.100.7", "198.51.100.8", "203.0.113.1");
        verify(dns, never()).query(anyString(), any(RecordType.class));
    }

    @Test
    void 중복된_사용자_입력_IP는_제거된다() {
        Optional<TargetIpResolver.TargetIps> result =
                resolver.resolve(DOMAIN, List.of("198.51.100.7", "198.51.100.7"));

        assertThat(result).isPresent();
        assertThat(result.get().ips()).containsExactly("198.51.100.7");
    }

    @Test
    void 사용자_입력_IP의_앞뒤_공백은_제거된다() {
        Optional<TargetIpResolver.TargetIps> result = resolver.resolve(DOMAIN, List.of("  198.51.100.7  "));

        assertThat(result).isPresent();
        assertThat(result.get().ips()).containsExactly("198.51.100.7");
    }

    @Test
    void 공백_문자열만_있는_IP_목록은_입력으로_취급하지_않고_MX에서_도출한다() {
        when(dns.query(DOMAIN, RecordType.MX)).thenReturn(answer("10 mx1.example.com"));
        when(dns.query("mx1.example.com", RecordType.A)).thenReturn(answer("203.0.113.10"));

        Optional<TargetIpResolver.TargetIps> result = resolver.resolve(DOMAIN, List.of("   "));

        assertThat(result).isPresent();
        assertThat(result.get().ips()).containsExactly("203.0.113.10");
    }

    @Test
    void IP_미입력시_우선순위가_가장_높은_MX의_A레코드를_사용한다() {
        when(dns.query(DOMAIN, RecordType.MX))
                .thenReturn(answer("30 mx3.example.com", "10 mx1.example.com", "20 mx2.example.com"));
        when(dns.query("mx1.example.com", RecordType.A)).thenReturn(answer("203.0.113.10"));

        Optional<TargetIpResolver.TargetIps> result = resolver.resolve(DOMAIN, null);

        assertThat(result).isPresent();
        assertThat(result.get().ips()).containsExactly("203.0.113.10");
        assertThat(result.get().source()).contains("mx1.example.com").contains("A 레코드");
    }

    @Test
    void A레코드가_여러개면_전부_대상이_된다() {
        when(dns.query(DOMAIN, RecordType.MX)).thenReturn(answer("10 mx1.example.com"));
        when(dns.query("mx1.example.com", RecordType.A)).thenReturn(answer("203.0.113.10", "203.0.113.11"));

        Optional<TargetIpResolver.TargetIps> result = resolver.resolve(DOMAIN, null);

        assertThat(result).isPresent();
        assertThat(result.get().ips()).containsExactly("203.0.113.10", "203.0.113.11");
    }

    @Test
    void MX_호스트의_AAAA_레코드도_대상에_포함된다() {
        when(dns.query(DOMAIN, RecordType.MX)).thenReturn(answer("10 mx1.example.com"));
        when(dns.query("mx1.example.com", RecordType.A)).thenReturn(answer("203.0.113.10"));
        when(dns.query("mx1.example.com", RecordType.AAAA)).thenReturn(answer("2001:db8::10"));

        Optional<TargetIpResolver.TargetIps> result = resolver.resolve(DOMAIN, null);

        assertThat(result).isPresent();
        assertThat(result.get().ips()).containsExactly("203.0.113.10", "2001:db8::10");
        assertThat(result.get().source()).contains("A/AAAA");
    }

    @Test
    void AAAA만_있는_MX_호스트도_대상이_된다() {
        when(dns.query(DOMAIN, RecordType.MX)).thenReturn(answer("10 mx1.example.com"));
        when(dns.query("mx1.example.com", RecordType.AAAA)).thenReturn(answer("2001:db8::10"));

        assertThat(resolver.resolve(DOMAIN, null)).map(TargetIpResolver.TargetIps::ips)
                .contains(List.of("2001:db8::10"));
    }

    @Test
    void MX에서_도출된_사설_IP는_대상에서_제외된다() {
        when(dns.query(DOMAIN, RecordType.MX)).thenReturn(answer("10 mx1.example.com"));
        when(dns.query("mx1.example.com", RecordType.A)).thenReturn(answer("192.168.0.10", "203.0.113.10"));

        assertThat(resolver.resolve(DOMAIN, null)).map(TargetIpResolver.TargetIps::ips)
                .contains(List.of("203.0.113.10"));
    }

    @Test
    void MX가_사설_IP로만_해석되면_대상_IP를_찾지_못한다() {
        when(dns.query(DOMAIN, RecordType.MX)).thenReturn(answer("10 mx1.example.com"));
        when(dns.query("mx1.example.com", RecordType.A)).thenReturn(answer("192.168.0.10"));

        assertThat(resolver.resolve(DOMAIN, null)).isEmpty();
    }

    @Test
    void Null_MX는_후보에서_제외된다() {
        when(dns.query(DOMAIN, RecordType.MX)).thenReturn(answer("0 .", "10 mx1.example.com"));
        when(dns.query("mx1.example.com", RecordType.A)).thenReturn(answer("203.0.113.10"));

        assertThat(resolver.resolve(DOMAIN, null)).map(TargetIpResolver.TargetIps::ips)
                .contains(List.of("203.0.113.10"));
    }

    @Test
    void Null_MX만_있으면_대상_IP를_찾지_못한다() {
        when(dns.query(DOMAIN, RecordType.MX)).thenReturn(answer("0 ."));

        assertThat(resolver.resolve(DOMAIN, null)).isEmpty();
    }

    @Test
    void MX_레코드가_없으면_비어있다() {
        when(dns.query(DOMAIN, RecordType.MX)).thenReturn(EMPTY);

        assertThat(resolver.resolve(DOMAIN, null)).isEmpty();
    }

    @Test
    void MX_조회가_실패하면_비어있다() {
        when(dns.query(DOMAIN, RecordType.MX)).thenReturn(DnsAnswer.of(DnsRcode.TIMEOUT));

        assertThat(resolver.resolve(DOMAIN, null)).isEmpty();
    }

    @Test
    void MX는_있으나_A레코드가_없으면_비어있다() {
        when(dns.query(DOMAIN, RecordType.MX)).thenReturn(answer("10 mx1.example.com"));

        assertThat(resolver.resolve(DOMAIN, null)).isEmpty();
    }

    @Test
    void A_조회가_실패하면_비어있다() {
        when(dns.query(DOMAIN, RecordType.MX)).thenReturn(answer("10 mx1.example.com"));
        when(dns.query("mx1.example.com", RecordType.A)).thenReturn(DnsAnswer.of(DnsRcode.SERVFAIL));

        assertThat(resolver.resolve(DOMAIN, null)).isEmpty();
    }

    @Test
    void 형식이_깨진_MX_값은_무시된다() {
        when(dns.query(DOMAIN, RecordType.MX))
                .thenReturn(answer("mx-broken.example.com", "abc mx-bad.example.com", "10 mx1.example.com"));
        when(dns.query("mx1.example.com", RecordType.A)).thenReturn(answer("203.0.113.10"));

        assertThat(resolver.resolve(DOMAIN, null)).map(TargetIpResolver.TargetIps::ips)
                .contains(List.of("203.0.113.10"));
    }
}
