package io.github.potwings.mailcheck.mail.util;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.regex.Pattern;

/**
 * Detects client IPs that cannot be diagnosed: hairpin NAT rewrites the source
 * to the router's private address (infra-work.md §6.1), and with a non-public
 * IP every SPF/PTR/RBL check would misfire. Unparseable input is treated as
 * non-public (fail-safe: better to reject than to misdiagnose).
 */
public final class IpClassifier {

    private static final Pattern IPV4 = Pattern.compile("^\\d{1,3}(\\.\\d{1,3}){3}$");

    private IpClassifier() {
    }

    public static boolean isNonPublic(String ip) {
        if (ip == null || ip.isBlank()) {
            return true;
        }
        String literal = ip.trim();
        // Guard against hostnames and bad octets ("300.1.1.1"): InetAddress.getByName
        // would fall back to a DNS lookup for anything that is not a clean literal.
        if (IPV4.matcher(literal).matches()) {
            for (String octet : literal.split("\\.")) {
                if (Integer.parseInt(octet) > 255) {
                    return true;
                }
            }
        } else if (!literal.contains(":")) {
            return true;
        }
        InetAddress addr;
        try {
            addr = InetAddress.getByName(literal);
        } catch (UnknownHostException e) {
            return true;
        }
        if (addr.isAnyLocalAddress() || addr.isLoopbackAddress()
                || addr.isLinkLocalAddress() || addr.isSiteLocalAddress()) {
            return true;
        }
        // IPv6 ULA fc00::/7 — not covered by isSiteLocalAddress (that is fec0::/10)
        byte[] bytes = addr.getAddress();
        return bytes.length == 16 && (bytes[0] & 0xFE) == 0xFC;
    }
}
