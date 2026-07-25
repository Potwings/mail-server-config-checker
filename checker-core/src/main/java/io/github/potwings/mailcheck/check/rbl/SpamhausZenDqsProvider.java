package io.github.potwings.mailcheck.check.rbl;

import io.github.potwings.mailcheck.dns.DnsAnswer;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Spamhaus ZEN via DQS (Data Query Service).
 *
 * Spamhaus blocks queries arriving through public resolvers (and some ISP
 * infrastructure like KT) and answers with 127.255.255.x error codes instead —
 * which naive checkers misread as "not listed". DQS puts the account key in the
 * query name, so answers stay reliable regardless of resolver path.
 */
public class SpamhausZenDqsProvider implements RblProvider {

    private static final Map<String, String> LISTINGS = Map.of(
            "127.0.0.2", "SBL (스팸 발신 소스)",
            "127.0.0.3", "SBL CSS (스냅샷/저평판 발신)",
            "127.0.0.4", "XBL (감염/봇넷)",
            "127.0.0.5", "XBL (감염/봇넷)",
            "127.0.0.6", "XBL (감염/봇넷)",
            "127.0.0.7", "XBL (감염/봇넷)",
            "127.0.0.9", "SBL DROP (하이재킹 대역)",
            "127.0.0.10", "PBL (정책 차단 — 동적/가정용 IP 대역)",
            "127.0.0.11", "PBL (ISP 관리 대역)");

    private final String dqsKey;

    public SpamhausZenDqsProvider(String dqsKey) {
        this.dqsKey = dqsKey == null ? "" : dqsKey.trim();
    }

    @Override
    public String name() {
        return "Spamhaus ZEN (DQS)";
    }

    @Override
    public boolean enabled() {
        return !dqsKey.isBlank();
    }

    @Override
    public String disabledReason() {
        return "DQS 키 미설정 — 무료 키 발급(https://www.spamhaus.com/free-trial/) 후 "
                + "SPAMHAUS_DQS_KEY 환경변수 또는 application-local.yml의 mailcheck.rbl.spamhaus-dqs-key로 설정하세요. "
                + "공용 리졸버 경유 zen.spamhaus.org 조회는 차단되어 오판을 유발하므로 지원하지 않습니다";
    }

    @Override
    public String queryName(String reversedIp) {
        return reversedIp + "." + dqsKey + ".zen.dq.spamhaus.net";
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
            if (code.startsWith("127.255.255.")) {
                // Query rejected (public resolver, bad key, volume limit) — NOT "clean".
                return RblVerdict.error("DQS 오류 코드 " + code + " — 쿼리가 거부됨(키/리졸버 문제). 미등재로 판단하면 안 됨");
            }
            String meaning = LISTINGS.get(code);
            listings.add(meaning != null ? meaning + " [" + code + "]" : "알 수 없는 리턴 코드 " + code);
        }
        return listings.isEmpty() ? RblVerdict.notListed() : RblVerdict.listed(listings);
    }
}
