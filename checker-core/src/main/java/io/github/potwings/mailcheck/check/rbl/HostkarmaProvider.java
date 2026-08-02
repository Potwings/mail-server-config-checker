package io.github.potwings.mailcheck.check.rbl;

import io.github.potwings.mailcheck.dns.DnsAnswer;

import java.util.ArrayList;
import java.util.List;

/**
 * Hostkarma (hostkarma.junkemailfilter.com). Unlike pure blacklists it also
 * returns positive/neutral codes — white(1)/yellow(3)/NOBL(5) mean "not a spam
 * source" and must NOT be reported as listed. Only black(2) and brown(4) are
 * negative listings. No registration required.
 */
public class HostkarmaProvider implements RblProvider {

    private final boolean enabled;

    public HostkarmaProvider(boolean enabled) {
        this.enabled = enabled;
    }

    @Override
    public String name() {
        return "Hostkarma";
    }

    @Override
    public boolean enabled() {
        return enabled;
    }

    @Override
    public String disabledReason() {
        return "설정에서 비활성화됨 (mailcheck.rbl.hostkarma-enabled)";
    }

    @Override
    public String queryName(String reversedIp) {
        return reversedIp + ".hostkarma.junkemailfilter.com";
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
            switch (code) {
                case "127.0.0.2" -> listings.add("블랙리스트 (스팸 발신 이력) [" + code + "]");
                case "127.0.0.4" -> listings.add("브라운리스트 (스팸/정상 혼재 발신) [" + code + "]");
                case "127.0.0.1", "127.0.0.3", "127.0.0.5" -> {
                    // white / yellow / NOBL — positive or neutral, not a listing.
                }
                default -> {
                    if (code.startsWith("127.0.0.")) {
                        listings.add("알 수 없는 리턴 코드 " + code);
                    }
                }
            }
        }
        return listings.isEmpty() ? RblVerdict.notListed()
                : RblVerdict.listed(listings, List.of(
                        "Hostkarma: 스팸 발송 원인을 해결한 뒤 https://ipadmin.junkemailfilter.com 에서 IP를 조회해 해제를 요청하세요"));
    }
}
