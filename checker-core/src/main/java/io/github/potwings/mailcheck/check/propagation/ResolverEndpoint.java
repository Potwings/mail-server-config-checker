package io.github.potwings.mailcheck.check.propagation;

/** A public/ISP recursive resolver probed during propagation checks. */
public record ResolverEndpoint(String name, String ip) {

    /** Parses "Google=8.8.8.8" style config entries. */
    public static ResolverEndpoint parse(String entry) {
        int eq = entry.indexOf('=');
        if (eq <= 0 || eq == entry.length() - 1) {
            throw new IllegalArgumentException("리졸버 설정 형식 오류 (이름=IP): " + entry);
        }
        return new ResolverEndpoint(entry.substring(0, eq).trim(), entry.substring(eq + 1).trim());
    }
}
