package io.github.potwings.mailcheck.check.dmarc;

import com.google.common.net.InternetDomainName;

/**
 * Organizational Domain per RFC 7489 §3.2, backed by Guava's Public Suffix List.
 */
public class OrgDomainResolver {

    public String organizationalDomain(String domain) {
        try {
            InternetDomainName idn = InternetDomainName.from(domain);
            if (idn.isUnderPublicSuffix()) {
                return idn.topPrivateDomain().toString();
            }
        } catch (IllegalArgumentException | IllegalStateException e) {
            // not a valid public-suffix-based name — fall back to the input as-is
        }
        return domain;
    }
}
