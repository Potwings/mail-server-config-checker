package io.github.potwings.mailcheck.check.ptr;

import io.github.potwings.mailcheck.api.Check;
import io.github.potwings.mailcheck.api.CheckContext;
import io.github.potwings.mailcheck.api.CheckResult;
import io.github.potwings.mailcheck.api.CheckStatus;
import io.github.potwings.mailcheck.dns.DnsAnswer;
import io.github.potwings.mailcheck.dns.DnsQueryService;
import io.github.potwings.mailcheck.dns.RecordType;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * PTR existence + Forward-Confirmed reverse DNS: PTR → hostname → A/AAAA must
 * come back to the original IP. Runs per target IP and keeps the worst status;
 * guidance is emitted once per failure kind, not per IP.
 * HELO matching needs an SMTP session → stage 2.
 */
public class PtrCheck implements Check {

    private final DnsQueryService dns;

    public PtrCheck(DnsQueryService dns) {
        this.dns = dns;
    }

    @Override
    public String id() {
        return "ptr";
    }

    @Override
    public String title() {
        return "PTR / FCrDNS";
    }

    @Override
    public CheckResult run(CheckContext ctx) {
        CheckResult.Builder b = CheckResult.builder(id(), title());

        if (!ctx.hasTargetIps()) {
            return b.status(CheckStatus.SKIP)
                    .evidence("검사 대상 IP를 확인할 수 없어 건너뜀 (MX 미존재 또는 해석 실패)")
                    .guidance("검사할 발신 서버 IP를 직접 입력하면 PTR 검사가 수행됩니다")
                    .build();
        }
        List<String> ips = ctx.targetIps();
        b.evidence("검사 대상 IP: " + String.join(", ", ips) + " (" + ctx.targetIpSource() + ")");

        boolean anyMissingPtr = false;
        boolean anyMultiPtr = false;
        boolean anyFcrdnsFail = false;
        boolean anyGeneric = false;
        for (String ip : ips) {
            // Prefix evidence with the IP only when there are several, so single-IP output stays clean.
            String tag = ips.size() > 1 ? "[" + ip + "] " : "";

            DnsAnswer ptr = dns.query(ip, RecordType.PTR);
            if (ptr.failed()) {
                b.atLeast(CheckStatus.ERROR).evidence(tag + "PTR 조회 실패 (" + ptr.rcode() + ")");
                continue;
            }
            if (!ptr.hasRecords()) {
                anyMissingPtr = true;
                b.atLeast(CheckStatus.FAIL)
                        .evidence(tag + "PTR(역방향 DNS) 레코드가 없음 — 다수의 수신 서버가 이를 스팸 신호로 취급");
                continue;
            }

            List<String> hosts = ptr.values();
            if (hosts.size() > 1) {
                anyMultiPtr = true;
                b.atLeast(CheckStatus.WARN)
                        .evidence(tag + "PTR 레코드가 " + hosts.size() + "개 — 일부 수신 서버는 다중 PTR을 불신함");
            }

            List<String> generic = hosts.stream().filter(h -> looksGeneric(h, ip)).toList();
            if (!generic.isEmpty()) {
                anyGeneric = true;
                b.atLeast(CheckStatus.WARN)
                        .evidence(tag + "PTR 호스트명이 ISP 기본(제네릭/동적) 패턴으로 보임: " + String.join(", ", generic));
            }

            boolean ipv6 = ip.contains(":");
            List<String> confirmed = new ArrayList<>();
            for (String host : hosts) {
                DnsAnswer forward = dns.query(host, ipv6 ? RecordType.AAAA : RecordType.A);
                if (forward.values().contains(ip)) {
                    confirmed.add(host);
                } else {
                    b.evidence(tag + "정방향 확인 실패: " + host + " → " +
                            (forward.hasRecords() ? String.join(", ", forward.values()) : "(A/AAAA 없음)")
                            + " ≠ " + ip);
                }
            }

            if (confirmed.isEmpty()) {
                anyFcrdnsFail = true;
                b.atLeast(CheckStatus.FAIL);
            } else {
                confirmed.forEach(h -> b.evidence(tag + "FCrDNS 확인: " + ip + " → " + h + " → " + ip));
            }
        }

        if (anyMissingPtr) {
            b.guidance("IP 소유자(ISP/호스팅/클라우드)에 역방향 DNS 등록을 요청하세요. 값은 발신 서버의 정식 호스트명이어야 합니다");
        }
        if (anyMultiPtr) {
            b.guidance("PTR은 발신 호스트명 하나만 남기는 것을 권장합니다");
        }
        if (anyFcrdnsFail) {
            b.guidance("PTR이 가리키는 호스트명의 A/AAAA 레코드가 원래 IP로 되돌아오도록 정/역방향을 맞추세요 (FCrDNS)");
        }
        if (anyGeneric) {
            b.guidance("제네릭/동적 패턴의 PTR은 FCrDNS가 성립해도 다수 수신 서버가 스팸 신호로 취급합니다 — "
                    + "mail.<도메인> 형태의 전용 호스트명으로 역방향 DNS를 변경하세요");
        }

        b.evidence("※ HELO/EHLO 명과 PTR 일치 여부는 SMTP 세션이 필요해 2단계(실메일 모드)에서 검사");
        return b.build();
    }

    private static final Set<String> GENERIC_TOKENS = Set.of(
            "dynamic", "dyn", "dhcp", "pool", "ppp", "pppoe", "dsl", "adsl", "dialup", "cable");

    /** Heuristic for ISP-default reverse names: generic keywords, or the IP's octets embedded in order. */
    static boolean looksGeneric(String host, String ip) {
        List<String> tokens = Arrays.stream(host.toLowerCase(Locale.ROOT).split("[.\\-_]"))
                .map(t -> t.replaceFirst("^0+(?=.)", "")) // "090" → "90" 형태의 제로 패딩 무시
                .toList();
        if (tokens.stream().anyMatch(GENERIC_TOKENS::contains)) {
            return true;
        }
        if (ip.contains(":")) {
            return false;
        }
        String[] o = ip.split("\\.");
        List<String> fwd = List.of(o[0], o[1], o[2], o[3]);
        List<String> rev = List.of(o[3], o[2], o[1], o[0]);
        for (int i = 0; i + 4 <= tokens.size(); i++) {
            List<String> window = tokens.subList(i, i + 4);
            if (window.equals(fwd) || window.equals(rev)) {
                return true;
            }
        }
        return false;
    }
}
