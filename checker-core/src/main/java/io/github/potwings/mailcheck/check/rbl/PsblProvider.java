package io.github.potwings.mailcheck.check.rbl;

import io.github.potwings.mailcheck.dns.DnsAnswer;

import java.util.List;

/**
 * PSBL — Passive Spam Block List (psbl.surriel.com).
 * Spamtrap-driven; no registration required, free for any query volume.
 */
public class PsblProvider implements RblProvider {

    private final boolean enabled;

    public PsblProvider(boolean enabled) {
        this.enabled = enabled;
    }

    @Override
    public String name() {
        return "PSBL";
    }

    @Override
    public boolean enabled() {
        return enabled;
    }

    @Override
    public String disabledReason() {
        return "설정에서 비활성화됨 (mailcheck.rbl.psbl-enabled)";
    }

    @Override
    public String queryName(String reversedIp) {
        return reversedIp + ".psbl.surriel.com";
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
                .map(v -> "PSBL 등재 (스팸트랩 수신 이력) [" + v + "]")
                .toList();
        return hits.isEmpty() ? RblVerdict.notListed() : RblVerdict.listed(hits);
    }
}
