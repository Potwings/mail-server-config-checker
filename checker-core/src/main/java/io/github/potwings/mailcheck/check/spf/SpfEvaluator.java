package io.github.potwings.mailcheck.check.spf;

import io.github.potwings.mailcheck.check.spf.SpfRecordParser.ParseResult;
import io.github.potwings.mailcheck.check.spf.SpfRecordParser.SpfTerm;
import io.github.potwings.mailcheck.dns.DnsAnswer;
import io.github.potwings.mailcheck.dns.DnsQueryService;
import io.github.potwings.mailcheck.dns.RecordType;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * RFC 7208 check_host() evaluation for a declared sending IP. Without a live
 * SMTP session the synthetic sender is postmaster@&lt;domain&gt;, so %{s}/%{l}/%{o}
 * expand from it and session-only macros (%{h}, %{p}, ...) make that one
 * mechanism un-evaluable — it is skipped with a note. With a session the real
 * sender and HELO feed %{s}/%{l}/%{o}/%{h}; only %{p} stays excluded.
 */
public class SpfEvaluator {

    public enum Verdict { PASS, FAIL, SOFTFAIL, NEUTRAL, PERMERROR, TEMPERROR }

    /**
     * Live SMTP session values for macro expansion.
     *
     * @param sender full envelope sender; for a bounce use postmaster@&lt;helo&gt;
     *               per RFC 7208 §2.4
     * @param helo   HELO/EHLO name as claimed by the client; null when unknown
     */
    public record SmtpSession(String sender, String helo) {
    }

    /**
     * @param matched the deciding mechanism as written in the record (null when the
     *                default result applied or the error is not tied to one term)
     * @param notes   findings worth surfacing as evidence (skipped mechanisms, ...)
     */
    public record Evaluation(Verdict verdict, String matched, List<String> notes) {
    }

    private static final Pattern MACRO = Pattern.compile("%\\{([a-zA-Z])(\\d*)(r?)([.\\-+,/_=]*)}");
    private static final int MAX_NAMES_PER_MECHANISM = 10;

    private final DnsQueryService dns;
    private final SpfRecordParser parser = new SpfRecordParser();

    public SpfEvaluator(DnsQueryService dns) {
        this.dns = dns;
    }

    public Evaluation evaluate(String ip, String domain, List<SpfTerm> terms) {
        return evaluate(ip, domain, terms, null);
    }

    public Evaluation evaluate(String ip, String domain, List<SpfTerm> terms, SmtpSession session) {
        State st = new State();
        st.session = session;
        try {
            st.ip = InetAddress.getByName(ip);
        } catch (UnknownHostException e) {
            return new Evaluation(Verdict.PERMERROR, null, List.of("IP 리터럴 해석 실패: " + ip));
        }
        st.ipLiteral = ip;
        st.ipv6 = st.ip instanceof Inet6Address;
        st.visited.add(domain.toLowerCase(Locale.ROOT));
        Outcome o = checkHost(domain, terms, st, 0);
        return new Evaluation(o.verdict(), o.matched(), List.copyOf(st.notes));
    }

    private record Outcome(Verdict verdict, String matched) {
    }

    private enum Match { MATCHED, NO, SKIPPED, TEMPERROR, PERMERROR }

    private static final class State {
        InetAddress ip;
        String ipLiteral;
        boolean ipv6;
        SmtpSession session;
        int lookups;
        int voids;
        boolean lastLookupVoid;
        boolean temperrorOnFetch;
        final List<String> notes = new ArrayList<>();
        final Set<String> visited = new HashSet<>();
    }

    private Outcome checkHost(String domain, List<SpfTerm> terms, State st, int depth) {
        if (depth > SpfLookupCounter.MAX_LOOKUPS) {
            return new Outcome(Verdict.PERMERROR, "include/redirect 중첩 깊이 초과");
        }
        for (SpfTerm t : terms) {
            if (t.modifier()) {
                continue;
            }
            Match m = switch (t.name()) {
                case "all" -> Match.MATCHED;
                case "ip4" -> matchIp4(t.value(), st);
                case "ip6" -> matchIp6(t.value(), st);
                case "a" -> matchA(t.value(), domain, st);
                case "mx" -> matchMx(t.value(), domain, st);
                case "ptr" -> matchPtr(t.value(), domain, st);
                case "exists" -> matchExists(t.value(), domain, st);
                case "include" -> matchInclude(t.value(), domain, st, depth);
                default -> Match.NO;
            };
            switch (m) {
                case MATCHED -> {
                    return new Outcome(qualifierVerdict(t.qualifier()), describe(t));
                }
                case TEMPERROR -> {
                    return new Outcome(Verdict.TEMPERROR, describe(t));
                }
                case PERMERROR -> {
                    return new Outcome(Verdict.PERMERROR, describe(t));
                }
                case NO, SKIPPED -> {
                }
            }
        }
        // Reached only when no "all" matched, so RFC 7208 §6.1's "redirect ignored
        // in presence of all" is already satisfied.
        Optional<SpfTerm> redirect = terms.stream()
                .filter(t -> t.modifier() && t.name().equals("redirect"))
                .findFirst();
        if (redirect.isPresent()) {
            return followRedirect(redirect.get().value(), domain, st, depth);
        }
        return new Outcome(Verdict.NEUTRAL, null);
    }

    // ---- mechanisms ----

    private Match matchIp4(String value, State st) {
        return !st.ipv6 && cidrMatch(st.ip, value) ? Match.MATCHED : Match.NO;
    }

    private Match matchIp6(String value, State st) {
        return st.ipv6 && cidrMatch(st.ip, value) ? Match.MATCHED : Match.NO;
    }

    private Match matchA(String value, String currentDomain, State st) {
        DualCidr spec = DualCidr.parse(value);
        String target = targetDomain(spec.domain(), currentDomain, st);
        if (target == null) {
            return Match.SKIPPED;
        }
        if (overLookupLimit(st)) {
            return Match.PERMERROR;
        }
        return addressMatch(target, spec, st);
    }

    private Match matchMx(String value, String currentDomain, State st) {
        DualCidr spec = DualCidr.parse(value);
        String target = targetDomain(spec.domain(), currentDomain, st);
        if (target == null) {
            return Match.SKIPPED;
        }
        if (overLookupLimit(st)) {
            return Match.PERMERROR;
        }
        DnsAnswer mx = dns.query(target, RecordType.MX);
        if (mx.failed()) {
            return Match.TEMPERROR;
        }
        if (mx.isNxDomain() || !mx.hasRecords()) {
            return overVoidLimit(st) ? Match.PERMERROR : Match.NO;
        }
        List<String> hosts = mx.values().stream()
                .map(SpfEvaluator::mxHost)
                .filter(h -> h != null && !h.equals("."))
                .limit(MAX_NAMES_PER_MECHANISM)
                .toList();
        for (String host : hosts) {
            // Per RFC 7208 §4.6.4 the A/AAAA lookups for MX hosts have their own
            // cap (10 per mx term) and do not count toward the overall 10 limit.
            Match m = addressMatchNoCount(host, spec, st);
            if (m != Match.NO) {
                return m;
            }
        }
        return Match.NO;
    }

    private Match matchPtr(String value, String currentDomain, State st) {
        String target = targetDomain(value, currentDomain, st);
        if (target == null) {
            return Match.SKIPPED;
        }
        if (overLookupLimit(st)) {
            return Match.PERMERROR;
        }
        DnsAnswer ptr = dns.query(st.ipLiteral, RecordType.PTR);
        // RFC 7208 §5.5: on PTR lookup error or no records, the mechanism does not match.
        if (ptr.failed() || !ptr.hasRecords()) {
            return Match.NO;
        }
        String suffix = target.toLowerCase(Locale.ROOT);
        for (String host : ptr.values().stream().limit(MAX_NAMES_PER_MECHANISM).toList()) {
            DnsAnswer forward = dns.query(host, st.ipv6 ? RecordType.AAAA : RecordType.A);
            if (!forward.values().contains(st.ipLiteral)) {
                continue;
            }
            String h = host.toLowerCase(Locale.ROOT);
            if (h.equals(suffix) || h.endsWith("." + suffix)) {
                return Match.MATCHED;
            }
        }
        return Match.NO;
    }

    private Match matchExists(String value, String currentDomain, State st) {
        String target = expand(value, currentDomain, st);
        if (target == null) {
            return Match.SKIPPED;
        }
        if (overLookupLimit(st)) {
            return Match.PERMERROR;
        }
        // exists: always queries A regardless of the connecting IP family (RFC 7208 §5.7).
        DnsAnswer ans = dns.query(target, RecordType.A);
        if (ans.failed()) {
            return Match.TEMPERROR;
        }
        if (ans.hasRecords()) {
            return Match.MATCHED;
        }
        return overVoidLimit(st) ? Match.PERMERROR : Match.NO;
    }

    private Match matchInclude(String value, String currentDomain, State st, int depth) {
        String target = expand(value, currentDomain, st);
        if (target == null) {
            return Match.SKIPPED;
        }
        if (overLookupLimit(st)) {
            return Match.PERMERROR;
        }
        if (!st.visited.add(target.toLowerCase(Locale.ROOT))) {
            st.notes.add("include 순환 참조: " + target);
            return Match.PERMERROR;
        }
        List<SpfTerm> terms = fetchSpfTerms(target, st);
        if (terms == null) {
            return st.temperrorOnFetch ? Match.TEMPERROR : Match.PERMERROR;
        }
        Outcome o = checkHost(target, terms, st, depth + 1);
        // RFC 7208 §5.2: include matches only on recursive pass; fail/softfail/neutral
        // just mean "no match" and evaluation continues with the next mechanism.
        return switch (o.verdict()) {
            case PASS -> Match.MATCHED;
            case FAIL, SOFTFAIL, NEUTRAL -> Match.NO;
            case TEMPERROR -> Match.TEMPERROR;
            case PERMERROR -> Match.PERMERROR;
        };
    }

    private Outcome followRedirect(String value, String currentDomain, State st, int depth) {
        String target = expand(value, currentDomain, st);
        if (target == null) {
            return new Outcome(Verdict.NEUTRAL, null);
        }
        if (overLookupLimit(st)) {
            return new Outcome(Verdict.PERMERROR, "redirect=" + value);
        }
        if (!st.visited.add(target.toLowerCase(Locale.ROOT))) {
            st.notes.add("redirect 순환 참조: " + target);
            return new Outcome(Verdict.PERMERROR, "redirect=" + value);
        }
        List<SpfTerm> terms = fetchSpfTerms(target, st);
        if (terms == null) {
            // RFC 7208 §6.1: a redirect target without a usable SPF record is permerror.
            return new Outcome(st.temperrorOnFetch ? Verdict.TEMPERROR : Verdict.PERMERROR,
                    "redirect=" + value);
        }
        return checkHost(target, terms, st, depth + 1);
    }

    // ---- helpers ----

    /** @return the parsed terms, or null with st.temperrorOnFetch set accordingly */
    private List<SpfTerm> fetchSpfTerms(String domain, State st) {
        st.temperrorOnFetch = false;
        DnsAnswer ans = dns.query(domain, RecordType.TXT);
        if (ans.failed()) {
            st.temperrorOnFetch = true;
            st.notes.add(domain + " TXT 조회 실패(" + ans.rcode() + ")");
            return null;
        }
        List<String> spf = ans.values().stream().filter(SpfRecordParser::isSpfRecord).toList();
        if (ans.isNxDomain() || spf.isEmpty()) {
            st.voids++;
            st.notes.add(domain + " 에 SPF 레코드가 없음");
            return null;
        }
        if (spf.size() > 1) {
            st.notes.add(domain + " 에 SPF 레코드가 " + spf.size() + "개 중복");
            return null;
        }
        ParseResult parsed = parser.parse(spf.get(0));
        if (!parsed.errors().isEmpty()) {
            st.notes.add(domain + " SPF 구문 오류: " + String.join("; ", parsed.errors()));
            return null;
        }
        return parsed.terms();
    }

    private Match addressMatch(String host, DualCidr spec, State st) {
        Match m = addressMatchNoCount(host, spec, st);
        if (m == Match.NO && st.lastLookupVoid && overVoidLimit(st)) {
            return Match.PERMERROR;
        }
        return m;
    }

    private Match addressMatchNoCount(String host, DualCidr spec, State st) {
        st.lastLookupVoid = false;
        DnsAnswer ans = dns.query(host, st.ipv6 ? RecordType.AAAA : RecordType.A);
        if (ans.failed()) {
            return Match.TEMPERROR;
        }
        if (ans.isNxDomain() || !ans.hasRecords()) {
            st.lastLookupVoid = true;
            return Match.NO;
        }
        int prefix = st.ipv6 ? spec.cidr6() : spec.cidr4();
        byte[] ipBytes = st.ip.getAddress();
        for (String v : ans.values()) {
            try {
                byte[] recBytes = InetAddress.getByName(v).getAddress();
                if (recBytes.length == ipBytes.length && prefixEquals(ipBytes, recBytes, prefix)) {
                    return Match.MATCHED;
                }
            } catch (UnknownHostException ignored) {
            }
        }
        return Match.NO;
    }

    /** Empty spec domain means "the current domain"; macros may make it un-evaluable (null). */
    private String targetDomain(String specDomain, String currentDomain, State st) {
        return specDomain.isBlank() ? currentDomain : expand(specDomain, currentDomain, st);
    }

    private boolean overLookupLimit(State st) {
        st.lookups++;
        if (st.lookups > SpfLookupCounter.MAX_LOOKUPS) {
            st.notes.add("DNS lookup " + SpfLookupCounter.MAX_LOOKUPS + "회 제한 초과 (permerror)");
            return true;
        }
        return false;
    }

    private boolean overVoidLimit(State st) {
        st.voids++;
        if (st.voids > SpfLookupCounter.MAX_VOID_LOOKUPS) {
            st.notes.add("void lookup " + SpfLookupCounter.MAX_VOID_LOOKUPS + "회 초과 (permerror)");
            return true;
        }
        return false;
    }

    private static Verdict qualifierVerdict(char qualifier) {
        return switch (qualifier) {
            case '-' -> Verdict.FAIL;
            case '~' -> Verdict.SOFTFAIL;
            case '?' -> Verdict.NEUTRAL;
            default -> Verdict.PASS;
        };
    }

    private static String describe(SpfTerm t) {
        String q = t.qualifier() == '+' ? "" : String.valueOf(t.qualifier());
        if (t.value().isBlank()) {
            return q + t.name();
        }
        String sep = t.value().startsWith("/") ? "" : ":";
        return q + t.name() + sep + t.value();
    }

    private static String mxHost(String mxValue) {
        String[] parts = mxValue.trim().split("\\s+", 2);
        return parts.length == 2 ? parts[1] : null;
    }

    // ---- ip / cidr ----

    private static boolean cidrMatch(InetAddress ip, String value) {
        String addr = value;
        int prefix = -1;
        int slash = value.indexOf('/');
        if (slash >= 0) {
            addr = value.substring(0, slash);
            try {
                prefix = Integer.parseInt(value.substring(slash + 1));
            } catch (NumberFormatException e) {
                return false;
            }
        }
        try {
            byte[] a = ip.getAddress();
            byte[] b = InetAddress.getByName(addr).getAddress();
            if (a.length != b.length) {
                return false;
            }
            return prefixEquals(a, b, prefix < 0 ? a.length * 8 : prefix);
        } catch (UnknownHostException e) {
            return false;
        }
    }

    private static boolean prefixEquals(byte[] a, byte[] b, int bits) {
        int max = a.length * 8;
        bits = Math.min(bits, max);
        int fullBytes = bits / 8;
        for (int i = 0; i < fullBytes; i++) {
            if (a[i] != b[i]) {
                return false;
            }
        }
        int rem = bits % 8;
        if (rem == 0) {
            return true;
        }
        int mask = 0xFF << (8 - rem);
        return (a[fullBytes] & mask) == (b[fullBytes] & mask);
    }

    /** a/mx dual-cidr spec: "", "/24", "//64", "dom", "dom/24", "dom/24//64", ... */
    record DualCidr(String domain, int cidr4, int cidr6) {
        static DualCidr parse(String value) {
            String domain = value;
            int c4 = 32;
            int c6 = 128;
            int slash = value.indexOf('/');
            if (slash >= 0) {
                domain = value.substring(0, slash);
                String cidrs = value.substring(slash + 1); // after first '/'
                String v4Part;
                String v6Part = null;
                int dbl = cidrs.indexOf('/');
                if (dbl >= 0) {
                    v4Part = cidrs.substring(0, dbl);
                    v6Part = cidrs.substring(dbl + 1);
                    if (v6Part.startsWith("/")) {
                        v6Part = v6Part.substring(1);
                    }
                } else {
                    v4Part = cidrs;
                }
                c4 = parseOr(v4Part, 32);
                c6 = parseOr(v6Part, 128);
            }
            return new DualCidr(domain, c4, c6);
        }

        private static int parseOr(String s, int fallback) {
            if (s == null || s.isBlank()) {
                return fallback;
            }
            try {
                return Integer.parseInt(s);
            } catch (NumberFormatException e) {
                return fallback;
            }
        }
    }

    // ---- macros ----

    /** @return null when the value needs data only a live SMTP session has (%{h}, %{p}, ...) */
    private String expand(String value, String domain, State st) {
        if (!value.contains("%")) {
            return value;
        }
        StringBuilder out = new StringBuilder();
        int i = 0;
        Matcher m = MACRO.matcher(value);
        while (i < value.length()) {
            char c = value.charAt(i);
            if (c != '%') {
                out.append(c);
                i++;
                continue;
            }
            if (i + 1 >= value.length()) {
                out.append(c);
                break;
            }
            char next = value.charAt(i + 1);
            if (next == '%') {
                out.append('%');
                i += 2;
            } else if (next == '_') {
                out.append(' ');
                i += 2;
            } else if (next == '-') {
                out.append("%20");
                i += 2;
            } else if (next == '{' && m.region(i, value.length()).lookingAt()) {
                String expanded = expandOne(m.group(1).charAt(0), m.group(2), !m.group(3).isEmpty(),
                        m.group(4), domain, st);
                if (expanded == null) {
                    return null;
                }
                out.append(expanded);
                i = m.end();
            } else {
                out.append(c);
                i++;
            }
        }
        return out.toString();
    }

    private String expandOne(char letter, String digits, boolean reverse, String delims,
                             String domain, State st) {
        String raw = switch (Character.toLowerCase(letter)) {
            case 'd' -> domain;
            case 'o' -> senderDomain(st, domain);
            case 's' -> sender(st, domain);
            case 'l' -> senderLocalPart(st);
            case 'i' -> ipMacro(st);
            case 'v' -> st.ipv6 ? "ip6" : "in-addr";
            case 'h' -> helo(st);
            default -> null;
        };
        if (raw == null) {
            st.notes.add("세션 의존 매크로 %{" + letter + "} 포함 — 해당 메커니즘은 평가에서 제외 (설정 점검에는 영향 적음)");
            return null;
        }
        List<String> labels = splitOn(raw, delims.isEmpty() ? "." : delims);
        if (reverse) {
            Collections.reverse(labels);
        }
        if (!digits.isEmpty()) {
            int n = Integer.parseInt(digits);
            if (n > 0 && n < labels.size()) {
                labels = labels.subList(labels.size() - n, labels.size());
            }
        }
        return String.join(".", labels);
    }

    // Session-backed macro sources: fall back to the synthetic postmaster@<domain>
    // sender when no session was supplied; %{h} has no synthetic substitute.

    private static String sender(State st, String domain) {
        if (st.session != null && st.session.sender() != null && !st.session.sender().isBlank()) {
            return st.session.sender();
        }
        return "postmaster@" + domain;
    }

    private static String senderLocalPart(State st) {
        String s = sender(st, "");
        int at = s.lastIndexOf('@');
        // RFC 7208 §7.2: a sender without a local part expands %{l} as "postmaster".
        return at <= 0 ? "postmaster" : s.substring(0, at);
    }

    private static String senderDomain(State st, String domain) {
        if (st.session == null) {
            return domain;
        }
        String s = sender(st, domain);
        int at = s.lastIndexOf('@');
        return at < 0 || at == s.length() - 1 ? domain : s.substring(at + 1);
    }

    private static String helo(State st) {
        if (st.session != null && st.session.helo() != null && !st.session.helo().isBlank()) {
            return st.session.helo();
        }
        return null;
    }

    private static String ipMacro(State st) {
        if (!st.ipv6) {
            return st.ip.getHostAddress();
        }
        // IPv6 %{i} is the dotted nibble form (RFC 7208 §7.3), e.g. 2.0.0.1.0.d.b.8...
        StringBuilder sb = new StringBuilder();
        for (byte b : st.ip.getAddress()) {
            if (sb.length() > 0) {
                sb.append('.');
            }
            sb.append(Character.forDigit((b >> 4) & 0xF, 16)).append('.')
                    .append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    private static List<String> splitOn(String s, String delims) {
        List<String> out = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (delims.indexOf(c) >= 0) {
                out.add(cur.toString());
                cur.setLength(0);
            } else {
                cur.append(c);
            }
        }
        out.add(cur.toString());
        return out;
    }
}
