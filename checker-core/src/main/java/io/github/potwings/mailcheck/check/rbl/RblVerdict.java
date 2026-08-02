package io.github.potwings.mailcheck.check.rbl;

import java.util.List;

/**
 * Interpretation of one RBL zone's DNS answer.
 * ERROR must never be collapsed into NOT_LISTED — e.g. Spamhaus returns
 * 127.255.255.x codes when the query itself was rejected.
 *
 * A LISTED verdict may carry zone-specific delisting guidance so the check
 * can tell the user how to get off that particular list.
 */
public record RblVerdict(Type type, List<String> listings, List<String> guidance, String detail) {

    public enum Type {
        LISTED,
        NOT_LISTED,
        ERROR,
        SKIPPED
    }

    public static RblVerdict listed(List<String> listings) {
        return new RblVerdict(Type.LISTED, listings, List.of(), null);
    }

    public static RblVerdict listed(List<String> listings, List<String> guidance) {
        return new RblVerdict(Type.LISTED, listings, guidance, null);
    }

    public static RblVerdict notListed() {
        return new RblVerdict(Type.NOT_LISTED, List.of(), List.of(), null);
    }

    public static RblVerdict error(String detail) {
        return new RblVerdict(Type.ERROR, List.of(), List.of(), detail);
    }

    public static RblVerdict skipped(String detail) {
        return new RblVerdict(Type.SKIPPED, List.of(), List.of(), detail);
    }
}
