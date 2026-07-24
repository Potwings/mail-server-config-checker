package io.github.potwings.mailcheck.check.rbl;

import io.github.potwings.mailcheck.dns.DnsAnswer;

import java.util.List;

/**
 * Barracuda Reputation Block List (b.barracudacentral.org).
 * Requires free registration of the querying DNS server's IP — unregistered
 * resolvers get no answer, so failures are reported as ERROR, never NOT_LISTED.
 */
public class BarracudaProvider implements RblProvider {

    private final boolean enabled;

    public BarracudaProvider(boolean enabled) {
        this.enabled = enabled;
    }

    @Override
    public String name() {
        return "Barracuda";
    }

    @Override
    public boolean enabled() {
        return enabled;
    }

    @Override
    public String disabledReason() {
        return "설정에서 비활성화됨 (mailcheck.rbl.barracuda-enabled)";
    }

    @Override
    public String queryName(String reversedIp) {
        return reversedIp + ".b.barracudacentral.org";
    }

    @Override
    public RblVerdict interpret(DnsAnswer answer) {
        if (answer.isNxDomain()) {
            return RblVerdict.notListed();
        }
        if (answer.failed()) {
            return RblVerdict.error("조회 실패 (" + answer.rcode()
                    + ") — 조회 DNS 서버 IP가 Barracuda에 미등록(https://barracudacentral.org/account/register)일 수 있음");
        }
        List<String> hits = answer.values().stream()
                .filter(v -> v.startsWith("127.0.0."))
                .map(v -> "Barracuda 등재 [" + v + "]")
                .toList();
        return hits.isEmpty() ? RblVerdict.notListed() : RblVerdict.listed(hits);
    }
}
