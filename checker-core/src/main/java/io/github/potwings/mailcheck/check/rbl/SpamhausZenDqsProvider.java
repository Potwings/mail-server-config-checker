package io.github.potwings.mailcheck.check.rbl;

import io.github.potwings.mailcheck.dns.DnsAnswer;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

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

    /** Sub-list-specific delisting steps — XBL codes 4~7 share one entry. */
    private static final Map<String, String> DELISTING = Map.of(
            "127.0.0.2", "SBL: 해당 IP에서 스팸 발송이 직접 관측된 등재입니다. 발송 원인(스팸 발송 프로그램, 탈취된 계정)을 제거한 뒤 "
                    + "https://check.spamhaus.org 에서 IP를 조회해 해제(delisting)를 요청하세요",
            "127.0.0.3", "CSS: 탈취된 계정·웹폼 악용·인증(SPF/DKIM) 미비 등 저평판 발송 패턴이 탐지된 등재입니다. "
                    + "원인을 제거하면 수일 내 자동 해제되며, https://check.spamhaus.org 에서 즉시 해제 요청도 가능합니다",
            "127.0.0.4", "XBL: 해당 IP의 장비가 악성코드/봇넷에 감염되었거나 오픈 프록시로 악용되고 있다는 뜻입니다. "
                    + "감염 장비를 찾아 치료한 뒤 https://check.spamhaus.org 에서 해제를 요청하세요",
            "127.0.0.9", "DROP: 하이재킹·범죄 활동 대역으로 분류된 IP 대역입니다. 정상 할당 대역이라면 ISP와 함께 Spamhaus에 이의를 제기해야 합니다",
            "127.0.0.10", "PBL: 스팸 발송 이력이 아니라 \"메일 서버 운영이 예정되지 않은 대역\"이라는 정책 등재입니다. "
                    + "고정 IP·정식 발신 대역 사용이 근본 해결책이며, 직접 운영하는 정당한 서버라면 https://check.spamhaus.org 에서 자가 해제할 수 있습니다");

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
    public boolean supportsIpv6() {
        return true;
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
        Set<String> guidance = new LinkedHashSet<>();
        for (String code : answer.values()) {
            if (code.startsWith("127.255.255.")) {
                // Query rejected (public resolver, bad key, volume limit) — NOT "clean".
                return RblVerdict.error("DQS 오류 코드 " + code + " — 쿼리가 거부됨(키/리졸버 문제). 미등재로 판단하면 안 됨");
            }
            String meaning = LISTINGS.get(code);
            listings.add(meaning != null ? meaning + " [" + code + "]" : "알 수 없는 리턴 코드 " + code);
            String steps = DELISTING.get(delistingKey(code));
            if (steps != null) {
                guidance.add(steps);
            }
        }
        return listings.isEmpty() ? RblVerdict.notListed() : RblVerdict.listed(listings, List.copyOf(guidance));
    }

    /** XBL codes 5~7 and PBL 11 share the delisting steps of 4 and 10 respectively. */
    private static String delistingKey(String code) {
        return switch (code) {
            case "127.0.0.5", "127.0.0.6", "127.0.0.7" -> "127.0.0.4";
            case "127.0.0.11" -> "127.0.0.10";
            default -> code;
        };
    }
}
