package io.github.potwings.mailcheck.check.spf;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Syntax-level parser for a single SPF record (RFC 7208). Parse errors map to permerror.
 */
public final class SpfRecordParser {

    /**
     * @param qualifier one of + - ~ ? (mechanisms only; '+' when omitted)
     * @param modifier  true for "name=value" modifiers (redirect, exp, unknown)
     */
    public record SpfTerm(char qualifier, String name, String value, boolean modifier) {
    }

    public record ParseResult(List<SpfTerm> terms, List<String> errors, List<String> warnings) {
    }

    private static final Set<String> MECHANISMS = Set.of("all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists");
    private static final Set<String> KNOWN_MODIFIERS = Set.of("redirect", "exp");
    private static final Pattern MODIFIER = Pattern.compile("^([a-zA-Z][a-zA-Z0-9._-]*)=(.*)$");
    private static final Pattern IP4 = Pattern.compile("^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$");

    public static boolean isSpfRecord(String txt) {
        String t = txt.trim().toLowerCase(Locale.ROOT);
        return t.equals("v=spf1") || t.startsWith("v=spf1 ");
    }

    public ParseResult parse(String record) {
        List<SpfTerm> terms = new ArrayList<>();
        List<String> errors = new ArrayList<>();
        List<String> warnings = new ArrayList<>();

        String trimmed = record == null ? "" : record.trim();
        if (trimmed.isBlank()) {
            errors.add("빈 레코드");
            return new ParseResult(terms, errors, warnings);
        }
        String[] tokens = trimmed.split("\\s+");
        if (!tokens[0].equalsIgnoreCase("v=spf1")) {
            errors.add("레코드가 v=spf1 로 시작하지 않음");
            return new ParseResult(terms, errors, warnings);
        }

        for (int i = 1; i < tokens.length; i++) {
            String token = tokens[i];
            char qualifier = '+';
            String body = token;
            if (!body.isEmpty() && "+-~?".indexOf(body.charAt(0)) >= 0) {
                qualifier = body.charAt(0);
                body = body.substring(1);
            }
            if (body.isEmpty()) {
                errors.add("빈 항목: \"" + token + "\"");
                continue;
            }

            Matcher mod = MODIFIER.matcher(body);
            // Mechanisms use ':' — a '=' before any ':' means this is a modifier.
            int eq = body.indexOf('=');
            int colon = body.indexOf(':');
            boolean isModifier = mod.matches() && eq >= 0 && (colon < 0 || eq < colon);

            if (isModifier) {
                if (qualifier != '+') {
                    errors.add("modifier에는 qualifier를 붙일 수 없음: " + token);
                    continue;
                }
                String name = mod.group(1).toLowerCase(Locale.ROOT);
                String value = mod.group(2);
                if (!KNOWN_MODIFIERS.contains(name)) {
                    if (MECHANISMS.contains(name)) {
                        // e.g. "ip4=1.2.3.4" — syntactically an unknown modifier, silently
                        // ignored by receivers, which is almost never what the author meant.
                        warnings.add("\"" + token + "\" 는 modifier 문법이라 수신 서버가 무시함 — \""
                                + name + ":" + value + "\" 의도였는지 확인 필요");
                    } else {
                        warnings.add("알 수 없는 modifier(무시됨): " + token);
                    }
                } else if (value.isBlank()) {
                    errors.add(name + " modifier에 값이 없음: " + token);
                    continue;
                }
                terms.add(new SpfTerm('+', name, value, true));
            } else {
                parseMechanism(token, body, qualifier, terms, errors);
            }
        }
        return new ParseResult(terms, errors, warnings);
    }

    private void parseMechanism(String token, String body, char qualifier,
                                List<SpfTerm> terms, List<String> errors) {
        String name;
        String value = "";
        int colon = body.indexOf(':');
        int slash = body.indexOf('/');
        if (colon >= 0 && (slash < 0 || colon < slash)) {
            name = body.substring(0, colon);
            value = body.substring(colon + 1);
        } else if (slash >= 0) {
            name = body.substring(0, slash);
            value = body.substring(slash);
        } else {
            name = body;
        }
        name = name.toLowerCase(Locale.ROOT);

        if (!MECHANISMS.contains(name)) {
            errors.add("알 수 없는 메커니즘: " + token);
            return;
        }
        switch (name) {
            case "include", "exists" -> {
                if (value.isBlank() || value.startsWith("/")) {
                    errors.add(name + " 메커니즘에 대상 도메인이 없음: " + token);
                    return;
                }
            }
            case "ip4" -> {
                if (!validIp4Cidr(value)) {
                    errors.add("ip4 형식 오류: " + token);
                    return;
                }
            }
            case "ip6" -> {
                if (!validIp6Cidr(value)) {
                    errors.add("ip6 형식 오류: " + token);
                    return;
                }
            }
            case "all" -> {
                if (!value.isBlank()) {
                    errors.add("all 메커니즘은 값을 가질 수 없음: " + token);
                    return;
                }
            }
            default -> {
            }
        }
        terms.add(new SpfTerm(qualifier, name, value, false));
    }

    private static boolean validIp4Cidr(String value) {
        if (value.isBlank()) {
            return false;
        }
        String addr = value;
        if (value.contains("/")) {
            String[] parts = value.split("/", 2);
            addr = parts[0];
            if (!validPrefix(parts[1], 32)) {
                return false;
            }
        }
        Matcher m = IP4.matcher(addr);
        if (!m.matches()) {
            return false;
        }
        for (int i = 1; i <= 4; i++) {
            if (Integer.parseInt(m.group(i)) > 255) {
                return false;
            }
        }
        return true;
    }

    private static boolean validIp6Cidr(String value) {
        if (value.isBlank()) {
            return false;
        }
        String addr = value;
        if (value.contains("/")) {
            String[] parts = value.split("/", 2);
            addr = parts[0];
            if (!validPrefix(parts[1], 128)) {
                return false;
            }
        }
        if (!addr.contains(":")) {
            return false;
        }
        try {
            // Colon-containing literals are parsed locally — no DNS lookup happens here.
            InetAddress.getByName(addr);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean validPrefix(String prefix, int max) {
        try {
            int p = Integer.parseInt(prefix);
            return p >= 0 && p <= max;
        } catch (NumberFormatException e) {
            return false;
        }
    }
}
