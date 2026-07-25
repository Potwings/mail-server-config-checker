package io.github.potwings.mailcheck.check.rbl;

import io.github.potwings.mailcheck.dns.DnsAnswer;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Spamhaus DBL (Domain Block List) via DQS — lists domains (not IPs) seen in
 * spam/phish/malware. 127.0.1.x return codes distinguish outright bad domains
 * from legitimate-but-abused ones. Reuses the same DQS key as ZEN; the key is
 * embedded in the query name and must never appear in evidence.
 */
public class SpamhausDblProvider implements DomainRblProvider {

    private static final Map<String, String> LISTINGS = Map.of(
            "127.0.1.2", "스팸 도메인",
            "127.0.1.4", "피싱 도메인",
            "127.0.1.5", "멀웨어 도메인",
            "127.0.1.6", "봇넷 C&C 도메인",
            "127.0.1.102", "악용된 정상 도메인 (스팸)",
            "127.0.1.103", "악용된 정상 도메인 (스팸 리다이렉터)",
            "127.0.1.104", "악용된 정상 도메인 (피싱)",
            "127.0.1.105", "악용된 정상 도메인 (멀웨어)",
            "127.0.1.106", "악용된 정상 도메인 (봇넷 C&C)");

    private final String dqsKey;

    public SpamhausDblProvider(String dqsKey) {
        this.dqsKey = dqsKey == null ? "" : dqsKey.trim();
    }

    @Override
    public String name() {
        return "Spamhaus DBL (DQS)";
    }

    @Override
    public boolean enabled() {
        return !dqsKey.isBlank();
    }

    @Override
    public String disabledReason() {
        return "DQS 키 미설정 — 무료 키 발급(https://www.spamhaus.com/free-trial/) 후 "
                + "SPAMHAUS_DQS_KEY 환경변수 또는 application-local.yml의 mailcheck.rbl.spamhaus-dqs-key로 설정하세요 "
                + "(ZEN과 동일한 키를 사용합니다)";
    }

    @Override
    public String queryName(String domain) {
        return domain + "." + dqsKey + ".dbl.dq.spamhaus.net";
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
            if (code.equals("127.0.1.255")) {
                return RblVerdict.error("DBL 오류 코드 " + code + " — IP 형태 쿼리 금지. 미등재로 판단하면 안 됨");
            }
            String meaning = LISTINGS.get(code);
            listings.add(meaning != null ? meaning + " [" + code + "]" : "알 수 없는 리턴 코드 " + code);
        }
        return listings.isEmpty() ? RblVerdict.notListed() : RblVerdict.listed(listings);
    }
}
