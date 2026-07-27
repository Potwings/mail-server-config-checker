package io.github.potwings.mailcheck.mail.check.dkim;

import io.github.potwings.mailcheck.api.Check;
import io.github.potwings.mailcheck.api.CheckContext;
import io.github.potwings.mailcheck.api.CheckResult;
import io.github.potwings.mailcheck.api.CheckStatus;
import io.github.potwings.mailcheck.dns.DnsAnswer;
import io.github.potwings.mailcheck.dns.DnsQueryService;
import io.github.potwings.mailcheck.dns.RecordType;
import org.apache.james.jdkim.api.Result;
import org.apache.james.jdkim.api.SignatureRecord;

import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * DKIM per RFC 6376: actual signature verification of message.eml (selector
 * taken from the DKIM-Signature header — the only reliable discovery, PRD
 * constraint 4) plus key-record lint: key length (RSA 1024 min / 2048
 * recommended, ed25519 exempt), revoked key (empty p=), test mode (t=y).
 */
public class DkimCheck implements Check {

    private final DnsQueryService dns;
    private final DkimVerificationSupport support;

    public DkimCheck(DnsQueryService dns) {
        this.dns = dns;
        this.support = new DkimVerificationSupport(dns);
    }

    @Override
    public String id() {
        return "dkim";
    }

    @Override
    public String title() {
        return "DKIM";
    }

    @Override
    public CheckResult run(CheckContext ctx) {
        CheckResult.Builder b = CheckResult.builder(id(), title());
        if (!ctx.hasEml()) {
            return b.status(CheckStatus.SKIP)
                    .evidence("메일 원문(message.eml)이 있어야 검사할 수 있음 — 실메일 수신 시 자동 수행")
                    .build();
        }

        DkimVerificationSupport.Outcome o = support.verify(ctx.emlPath());
        if (o.error() != null) {
            return b.status(CheckStatus.ERROR).evidence(o.error()).build();
        }
        if (o.noSignature()) {
            return b.status(CheckStatus.FAIL)
                    .evidence("DKIM-Signature 헤더가 없음 — 발신 서버가 메일에 서명하지 않음")
                    .guidance("메일 서버에 DKIM 서명(OpenDKIM, rspamd 등)을 설정하고 셀렉터 공개키를 "
                            + "<셀렉터>._domainkey.<도메인> TXT로 게시하세요")
                    .build();
        }

        int pass = 0;
        int fail = 0;
        Set<String> keyTargets = new LinkedHashSet<>();
        for (Result r : o.results()) {
            // Type.NONE = 서명 레코드 파싱 자체가 실패해 jDKIM이 d=invalid 센티널을 채운 경우
            if (r.getResultType() == Result.Type.NONE) {
                fail++;
                String reason = r.getErrorMessage() == null ? "원인 미상" : r.getErrorMessage();
                b.evidence("서명 레코드 처리 실패 — " + reason);
                continue;
            }
            SignatureRecord rec = r.getRecord();
            String d = rec != null && rec.getDToken() != null ? rec.getDToken().toString() : "?";
            String s = rec != null && rec.getSelector() != null ? rec.getSelector().toString() : "?";
            if (rec != null && !"?".equals(d) && !"?".equals(s)) {
                keyTargets.add(s + "|" + d);
            }
            if (r.isSuccess()) {
                pass++;
                String algo = rec.getHashKeyType() + "-" + rec.getHashMethod();
                b.evidence("서명 검증 성공: d=" + d + ", s=" + s + ", a=" + algo);
            } else {
                fail++;
                String reason = r.getErrorMessage() == null ? "원인 미상" : r.getErrorMessage();
                b.evidence("서명 검증 실패: d=" + d + ", s=" + s + " — " + reason);
            }
        }
        if (pass == 0) {
            b.status(CheckStatus.FAIL)
                    .guidance("유효한 DKIM 서명이 없습니다 — evidence의 실패 사유를 확인하세요. "
                            + "서명 후 본문/헤더를 변경하는 장비(게이트웨이, 포워딩)가 있으면 서명이 깨집니다");
        } else if (fail > 0) {
            b.atLeast(CheckStatus.WARN)
                    .guidance("일부 서명이 검증에 실패했습니다 — 실패한 셀렉터의 키 게시 상태와 서명 설정을 확인하세요");
        }

        for (String target : keyTargets) {
            String[] parts = target.split("\\|", 2);
            lintKeyRecord(parts[0], parts[1], b);
        }
        return b.build();
    }

    /** Key-record lint beyond what verification itself proves. */
    private void lintKeyRecord(String selector, String domain, CheckResult.Builder b) {
        String qname = selector + "._domainkey." + domain;
        DnsAnswer ans = dns.query(qname, RecordType.TXT);
        if (ans.failed()) {
            b.atLeast(CheckStatus.WARN).evidence("키 레코드 조회 실패: " + qname + " (" + ans.rcode() + ")");
            return;
        }
        List<String> records = ans.values().stream().filter(v -> v.contains("p=")).toList();
        if (records.isEmpty()) {
            b.atLeast(CheckStatus.FAIL)
                    .evidence("공개키 레코드가 없음: " + qname + " TXT")
                    .guidance("서명에 사용한 셀렉터의 공개키를 DNS에 게시하세요");
            return;
        }
        if (records.size() > 1) {
            b.atLeast(CheckStatus.WARN)
                    .evidence(qname + " 에 키 레코드가 " + records.size() + "개 — 하나만 게시하세요");
        }

        Map<String, String> tags = parseTags(records.get(0));
        String p = tags.get("p");
        if (p == null) {
            b.atLeast(CheckStatus.WARN).evidence(qname + ": p= 태그가 없어 유효하지 않은 키 레코드");
            return;
        }
        if (p.isEmpty()) {
            b.atLeast(CheckStatus.FAIL)
                    .evidence(qname + ": p= 가 빈 값 — 키가 폐기(revoked)된 상태 (RFC 6376 §3.6.1)")
                    .guidance("폐기된 셀렉터로 서명 중입니다 — 새 키를 게시하거나 서명 셀렉터를 변경하세요");
            return;
        }
        if (tags.getOrDefault("t", "").contains("y")) {
            b.atLeast(CheckStatus.WARN)
                    .evidence(qname + ": t=y 테스트 모드 — 일부 수신 서버가 서명을 평가에서 제외함")
                    .guidance("운영 전환이 끝났다면 키 레코드에서 t=y 플래그를 제거하세요");
        }

        String keyType = tags.getOrDefault("k", "rsa").toLowerCase(Locale.ROOT);
        if (keyType.equals("rsa")) {
            Integer bits = rsaKeyBits(p);
            if (bits == null) {
                b.atLeast(CheckStatus.WARN).evidence(qname + ": 공개키(p=) 파싱 실패 — RSA 키가 아니거나 손상됨");
            } else if (bits < 1024) {
                b.atLeast(CheckStatus.FAIL)
                        .evidence(qname + ": RSA 키 길이 " + bits + "비트 — 1024비트 미만은 위조 가능해 다수 수신 서버가 거부")
                        .guidance("2048비트 RSA 키로 교체하세요");
            } else if (bits < 2048) {
                b.atLeast(CheckStatus.WARN)
                        .evidence(qname + ": RSA 키 길이 " + bits + "비트 — 동작하지만 2048비트 권장")
                        .guidance("키 로테이션 시 2048비트 RSA 키로 교체를 권장합니다");
            } else {
                b.evidence(qname + ": RSA 키 길이 " + bits + "비트");
            }
        } else if (keyType.equals("ed25519")) {
            b.evidence(qname + ": Ed25519 키 (k=ed25519) — RSA 키 길이 기준 미적용");
        } else {
            b.atLeast(CheckStatus.WARN).evidence(qname + ": 알 수 없는 키 타입 k=" + keyType);
        }
    }

    /** DKIM tag=value list; FWS inside values (folded p=) is stripped. */
    static Map<String, String> parseTags(String record) {
        Map<String, String> tags = new LinkedHashMap<>();
        for (String part : record.split(";")) {
            int eq = part.indexOf('=');
            if (eq > 0) {
                String name = part.substring(0, eq).trim().toLowerCase(Locale.ROOT);
                String value = part.substring(eq + 1).replaceAll("\\s", "");
                tags.put(name, value);
            }
        }
        return tags;
    }

    /** Modulus bit length of a base64 SubjectPublicKeyInfo RSA key; null when undecodable. */
    static Integer rsaKeyBits(String base64Key) {
        try {
            byte[] der = Base64.getMimeDecoder().decode(base64Key);
            RSAPublicKey key = (RSAPublicKey) KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(der));
            return key.getModulus().bitLength();
        } catch (Exception e) {
            return null;
        }
    }
}
