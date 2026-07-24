package io.github.potwings.mailcheck.check.spf;

import io.github.potwings.mailcheck.check.spf.SpfRecordParser.ParseResult;
import io.github.potwings.mailcheck.check.spf.SpfRecordParser.SpfTerm;
import io.github.potwings.mailcheck.dns.DnsAnswer;
import io.github.potwings.mailcheck.dns.DnsQueryService;
import io.github.potwings.mailcheck.dns.RecordType;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Walks include/redirect recursively and enforces the RFC 7208 limits:
 * ≤10 DNS-querying terms (include, a, mx, ptr, exists, redirect) and ≤2 void lookups.
 */
public class SpfLookupCounter {

    public static final int MAX_LOOKUPS = 10;
    public static final int MAX_VOID_LOOKUPS = 2;

    private final DnsQueryService dns;
    private final SpfRecordParser parser = new SpfRecordParser();

    public SpfLookupCounter(DnsQueryService dns) {
        this.dns = dns;
    }

    /** @param fatal non-null when a permerror-level violation was found */
    public record CountResult(int lookups, int voidLookups, List<String> notes, String fatal) {
    }

    private static final class State {
        int lookups;
        int voids;
        final List<String> notes = new ArrayList<>();
        final Set<String> visited = new HashSet<>();
        String fatal;
    }

    public CountResult count(String domain, List<SpfTerm> terms) {
        State st = new State();
        st.visited.add(domain.toLowerCase(Locale.ROOT));
        walk(domain, terms, st, 0);
        return new CountResult(st.lookups, st.voids, List.copyOf(st.notes), st.fatal);
    }

    private void walk(String domain, List<SpfTerm> terms, State st, int depth) {
        if (st.fatal != null) {
            return;
        }
        if (depth > MAX_LOOKUPS) {
            st.fatal = "include/redirect 중첩 깊이 초과";
            return;
        }
        boolean hasAll = terms.stream().anyMatch(t -> !t.modifier() && t.name().equals("all"));

        for (SpfTerm term : terms) {
            if (st.fatal != null) {
                return;
            }
            if (term.modifier()) {
                if (term.name().equals("redirect")) {
                    if (hasAll) {
                        st.notes.add("redirect=" + term.value() + " 는 all 메커니즘이 있어 무시됨 (RFC 7208 §6.1)");
                        continue;
                    }
                    if (countOne(st)) {
                        return;
                    }
                    recurse(term.value(), domain, st, depth, "redirect");
                }
                continue;
            }
            switch (term.name()) {
                case "include" -> {
                    if (countOne(st)) {
                        return;
                    }
                    recurse(term.value(), domain, st, depth, "include");
                }
                case "a", "mx", "ptr", "exists" -> {
                    if (countOne(st)) {
                        return;
                    }
                }
                default -> {
                }
            }
        }
    }

    /** @return true when the walk must stop (limit exceeded) */
    private boolean countOne(State st) {
        st.lookups++;
        if (st.lookups > MAX_LOOKUPS) {
            st.fatal = "DNS lookup " + MAX_LOOKUPS + "회 제한 초과 (RFC 7208 §4.6.4, permerror)";
            return true;
        }
        return false;
    }

    private void recurse(String target, String currentDomain, State st, int depth, String kind) {
        String expanded = expandStaticMacros(target, currentDomain, st, kind);
        if (expanded == null) {
            return;
        }
        if (!st.visited.add(expanded.toLowerCase(Locale.ROOT))) {
            st.fatal = kind + " 순환 참조: " + expanded + " (permerror)";
            return;
        }

        DnsAnswer ans = dns.query(expanded, RecordType.TXT);
        if (ans.failed()) {
            st.notes.add(kind + " " + expanded + ": TXT 조회 실패(" + ans.rcode() + ") — lookup 카운트만 반영, 재귀 생략");
            return;
        }
        List<String> spf = ans.values().stream().filter(SpfRecordParser::isSpfRecord).toList();
        if (ans.isNxDomain() || spf.isEmpty()) {
            st.voids++;
            st.fatal = kind + " 대상 " + expanded + " 에 SPF 레코드가 없음 (RFC 7208, permerror)";
            return;
        }
        if (st.voids > MAX_VOID_LOOKUPS) {
            st.fatal = "void lookup " + MAX_VOID_LOOKUPS + "회 초과 (RFC 7208 §4.6.4, permerror)";
            return;
        }
        if (spf.size() > 1) {
            st.fatal = expanded + " 에 SPF 레코드가 " + spf.size() + "개 중복 (permerror)";
            return;
        }

        ParseResult parsed = parser.parse(spf.get(0));
        if (!parsed.errors().isEmpty()) {
            st.fatal = expanded + " SPF 구문 오류: " + String.join("; ", parsed.errors());
            return;
        }
        walk(expanded, parsed.terms(), st, depth + 1);
    }

    /**
     * Static lint can only expand macros that don't depend on the SMTP session.
     * Returns null (with a note) when session-dependent macros block recursion.
     */
    private String expandStaticMacros(String value, String domain, State st, String kind) {
        if (!value.contains("%")) {
            return value;
        }
        String expanded = value.replace("%{d}", domain);
        if (expanded.contains("%{")) {
            st.notes.add(kind + " " + value + ": 세션 의존 매크로 포함 — lookup 카운트만 반영, 재귀 생략 (완전 평가는 2단계)");
            return null;
        }
        return expanded.replace("%%", "%").replace("%_", " ").replace("%-", "%20");
    }
}
