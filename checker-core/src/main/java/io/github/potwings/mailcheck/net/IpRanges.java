package io.github.potwings.mailcheck.net;

import com.google.common.net.InetAddresses;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;

/**
 * Classifies IP literals that can never be a public mail server address
 * (private, loopback, CGNAT, ...). Parsing is literal-only — no DNS resolution.
 * Documentation ranges (TEST-NET, 2001:db8::/32) are intentionally NOT flagged:
 * they are the convention for examples/tests and harmless to query.
 */
public final class IpRanges {

    private IpRanges() {
    }

    /** Returns why the IP cannot be a public address, or null when it can (or the input is not an IP literal). */
    public static String nonRoutableReason(String ipLiteral) {
        InetAddress addr;
        try {
            addr = InetAddresses.forString(ipLiteral.trim());
        } catch (IllegalArgumentException e) {
            return null; // IP 리터럴이 아님 — 형식 검증은 호출자 몫
        }
        if (addr.isLoopbackAddress()) {
            return "루프백(127.0.0.0/8, ::1)";
        }
        if (addr.isAnyLocalAddress()) {
            return "미지정 주소(0.0.0.0, ::)";
        }
        if (addr.isLinkLocalAddress()) {
            return "링크로컬(169.254.0.0/16, fe80::/10)";
        }
        if (addr.isMulticastAddress()) {
            return "멀티캐스트 대역";
        }
        if (addr.isSiteLocalAddress()) {
            return "사설 대역(RFC 1918)";
        }
        byte[] b = addr.getAddress();
        if (addr instanceof Inet4Address) {
            int o1 = b[0] & 0xff;
            int o2 = b[1] & 0xff;
            if (o1 == 100 && o2 >= 64 && o2 <= 127) {
                return "CGNAT(100.64.0.0/10) — 통신사 공유 주소로 서버 운영 불가";
            }
            if (o1 >= 240) {
                return "예약 대역(240.0.0.0/4)";
            }
        } else if (addr instanceof Inet6Address) {
            if ((b[0] & 0xfe) == 0xfc) {
                return "IPv6 ULA(fc00::/7)";
            }
        }
        return null;
    }
}
