package io.github.potwings.mailcheck.web.api;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.net.IDN;
import java.net.InetAddress;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class InputValidator {

    private static final Pattern HOSTNAME =
            Pattern.compile("^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z][a-z0-9-]{1,62}$");
    private static final Pattern IPV4 =
            Pattern.compile("^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$");

    private InputValidator() {
    }

    /** Accepts bare domains, punycode/IDN, and pasted URLs; returns a normalized FQDN. */
    static String normalizeDomain(String raw) {
        if (raw == null || raw.isBlank()) {
            throw bad("domain 파라미터가 비어 있습니다");
        }
        String d = raw.trim().toLowerCase(Locale.ROOT)
                .replaceFirst("^[a-z][a-z0-9+.-]*://", "")
                .split("[/?#]")[0];
        if (d.endsWith(".")) {
            d = d.substring(0, d.length() - 1);
        }
        try {
            d = IDN.toASCII(d).toLowerCase(Locale.ROOT);
        } catch (IllegalArgumentException e) {
            throw bad("도메인 형식이 올바르지 않습니다: " + raw);
        }
        if (!HOSTNAME.matcher(d).matches()) {
            throw bad("도메인 형식이 올바르지 않습니다: " + raw);
        }
        return d;
    }

    /** Returns null for blank input; validates IPv4/IPv6 literal otherwise. */
    static String normalizeIp(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        String ip = raw.trim();
        Matcher v4 = IPV4.matcher(ip);
        if (v4.matches()) {
            for (int i = 1; i <= 4; i++) {
                if (Integer.parseInt(v4.group(i)) > 255) {
                    throw bad("IP 형식이 올바르지 않습니다: " + raw);
                }
            }
            return ip;
        }
        if (ip.contains(":")) {
            try {
                // Colon literals are parsed locally — no DNS resolution happens here.
                return InetAddress.getByName(ip).getHostAddress();
            } catch (Exception e) {
                throw bad("IP 형식이 올바르지 않습니다: " + raw);
            }
        }
        throw bad("IP 형식이 올바르지 않습니다: " + raw);
    }

    private static ResponseStatusException bad(String message) {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, message);
    }
}
