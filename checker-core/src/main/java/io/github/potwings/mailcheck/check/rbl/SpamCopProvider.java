package io.github.potwings.mailcheck.check.rbl;

import io.github.potwings.mailcheck.dns.DnsAnswer;

import java.util.List;

/** SpamCop Blocking List (bl.spamcop.net). */
public class SpamCopProvider implements RblProvider {

    private final boolean enabled;

    public SpamCopProvider(boolean enabled) {
        this.enabled = enabled;
    }

    @Override
    public String name() {
        return "SpamCop";
    }

    @Override
    public boolean enabled() {
        return enabled;
    }

    @Override
    public String disabledReason() {
        return "설정에서 비활성화됨 (mailcheck.rbl.spamcop-enabled)";
    }

    @Override
    public String queryName(String reversedIp) {
        return reversedIp + ".bl.spamcop.net";
    }

    @Override
    public RblVerdict interpret(DnsAnswer answer) {
        if (answer.isNxDomain()) {
            return RblVerdict.notListed();
        }
        if (answer.failed()) {
            return RblVerdict.error("조회 실패 (" + answer.rcode() + ")");
        }
        List<String> hits = answer.values().stream()
                .filter(v -> v.startsWith("127.0.0."))
                .map(v -> "SpamCop 등재 [" + v + "]")
                .toList();
        return hits.isEmpty() ? RblVerdict.notListed() : RblVerdict.listed(hits);
    }
}
