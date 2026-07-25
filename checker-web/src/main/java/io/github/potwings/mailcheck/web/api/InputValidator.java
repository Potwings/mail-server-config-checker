package io.github.potwings.mailcheck.web.api;

import io.github.potwings.mailcheck.net.IpRanges;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.net.IDN;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.List;
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

    // Generous ceiling: covers real outbound IP pools while capping RBL query
    // amplification (providers × IPs per request — Spamhaus DQS quota).
    static final int MAX_TARGET_IPS = 20;

    /**
     * Returns an empty list for blank input; otherwise splits on commas and
     * validates each IPv4/IPv6 literal. Duplicates are removed, order kept.
     */
    static List<String> normalizeIps(String raw) {
        if (raw == null || raw.isBlank()) {
            return List.of();
        }
        List<String> ips = Arrays.stream(raw.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .distinct()
                .map(InputValidator::normalizeIp)
                .toList();
        if (ips.size() > MAX_TARGET_IPS) {
            throw bad("IP는 최대 " + MAX_TARGET_IPS + "개까지 입력할 수 있습니다 (입력됨: " + ips.size() + "개)");
        }
        return ips;
    }

    /** Validates a single IPv4/IPv6 literal and rejects private/reserved ranges. */
    private static String normalizeIp(String raw) {
        String ip = raw.trim();
        Matcher v4 = IPV4.matcher(ip);
        if (v4.matches()) {
            for (int i = 1; i <= 4; i++) {
                if (Integer.parseInt(v4.group(i)) > 255) {
                    throw bad("IP 형식이 올바르지 않습니다: " + raw);
                }
            }
            return requirePublic(ip, raw);
        }
        if (ip.contains(":")) {
            try {
                // Colon literals are parsed locally — no DNS resolution happens here.
                return requirePublic(InetAddress.getByName(ip).getHostAddress(), raw);
            } catch (ResponseStatusException e) {
                throw e;
            } catch (Exception e) {
                throw bad("IP 형식이 올바르지 않습니다: " + raw);
            }
        }
        throw bad("IP 형식이 올바르지 않습니다: " + raw);
    }

    /** PTR/RBL results for private/reserved IPs are meaningless (some RBL zones even list them). */
    private static String requirePublic(String ip, String raw) {
        String reason = IpRanges.nonRoutableReason(ip);
        if (reason != null) {
            throw bad("공인 IP가 아닙니다 — " + reason + ": " + raw + ". 발신 서버의 공인 IP를 입력하세요");
        }
        return ip;
    }

    private static ResponseStatusException bad(String message) {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, message);
    }
}
