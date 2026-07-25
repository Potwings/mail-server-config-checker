package io.github.potwings.mailcheck.check.rbl;

import io.github.potwings.mailcheck.dns.DnsAnswer;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Mailspike blacklist (bl.mailspike.net) — combines the Z (zombie/spam source)
 * list with the reputation list's bad tiers (L3–L5). No registration required.
 */
public class MailspikeProvider implements RblProvider {

    private static final Map<String, String> LISTINGS = Map.of(
            "127.0.0.2", "Z 리스트 (스팸 발신/좀비 IP)",
            "127.0.0.10", "평판 최악 (L5)",
            "127.0.0.11", "평판 매우 나쁨 (L4)",
            "127.0.0.12", "평판 나쁨 (L3)");

    private final boolean enabled;

    public MailspikeProvider(boolean enabled) {
        this.enabled = enabled;
    }

    @Override
    public String name() {
        return "Mailspike";
    }

    @Override
    public boolean enabled() {
        return enabled;
    }

    @Override
    public String disabledReason() {
        return "설정에서 비활성화됨 (mailcheck.rbl.mailspike-enabled)";
    }

    @Override
    public String queryName(String reversedIp) {
        return reversedIp + ".bl.mailspike.net";
    }

    @Override
    public RblVerdict interpret(DnsAnswer answer) {
        if (answer.isNxDomain()) {
            return RblVerdict.notListed();
        }
        if (answer.failed()) {
            return RblVerdict.error("조회 실패 (" + answer.rcode() + ")");
        }
        List<String> listings = new ArrayList<>();
        for (String code : answer.values()) {
            if (!code.startsWith("127.0.0.")) {
                continue;
            }
            String meaning = LISTINGS.get(code);
            listings.add(meaning != null ? meaning + " [" + code + "]" : "알 수 없는 리턴 코드 " + code);
        }
        return listings.isEmpty() ? RblVerdict.notListed() : RblVerdict.listed(listings);
    }
}
