package io.github.potwings.mailcheck.mail.util;

import java.net.IDN;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Domain normalization for values extracted from mail (From: header domain,
 * MAIL FROM domain): lowercase + punycode + hostname shape check. Unlike the
 * old web-form validator there is no URL stripping — these are never URLs.
 */
public final class Domains {

    private static final Pattern HOSTNAME =
            Pattern.compile("^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z][a-z0-9-]{1,62}$");

    private Domains() {
    }

    /** @return the normalized FQDN, or null when the input is not a usable domain */
    public static String normalize(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        String d = raw.trim().toLowerCase(Locale.ROOT);
        if (d.endsWith(".")) {
            d = d.substring(0, d.length() - 1);
        }
        try {
            d = IDN.toASCII(d).toLowerCase(Locale.ROOT);
        } catch (IllegalArgumentException e) {
            return null;
        }
        return HOSTNAME.matcher(d).matches() ? d : null;
    }
}
