package io.github.potwings.mailcheck.check.ptr;

import io.github.potwings.mailcheck.api.Check;
import io.github.potwings.mailcheck.api.CheckContext;
import io.github.potwings.mailcheck.api.CheckResult;
import io.github.potwings.mailcheck.api.CheckStatus;
import io.github.potwings.mailcheck.dns.DnsAnswer;
import io.github.potwings.mailcheck.dns.DnsQueryService;
import io.github.potwings.mailcheck.dns.RecordType;

import java.util.ArrayList;
import java.util.List;

/**
 * PTR existence + Forward-Confirmed reverse DNS: PTR → hostname → A/AAAA must
 * come back to the original IP. HELO matching needs an SMTP session → stage 2.
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

        if (!ctx.hasTargetIp()) {
            return b.status(CheckStatus.SKIP)
                    .evidence("검사 대상 IP를 확인할 수 없어 건너뜀 (MX 미존재 또는 해석 실패)")
                    .guidance("검사할 발신 서버 IP를 직접 입력하면 PTR 검사가 수행됩니다")
                    .build();
        }
        String ip = ctx.targetIp();
        b.evidence("검사 대상 IP: " + ip + " (" + ctx.targetIpSource() + ")");

        DnsAnswer ptr = dns.query(ip, RecordType.PTR);
        if (ptr.failed()) {
            return b.status(CheckStatus.ERROR).evidence("PTR 조회 실패 (" + ptr.rcode() + ")").build();
        }
        if (!ptr.hasRecords()) {
            return b.status(CheckStatus.FAIL)
                    .evidence("PTR(역방향 DNS) 레코드가 없음 — 다수의 수신 서버가 이를 스팸 신호로 취급")
                    .guidance("IP 소유자(ISP/호스팅/클라우드)에 역방향 DNS 등록을 요청하세요. 값은 발신 서버의 정식 호스트명이어야 합니다")
                    .build();
        }

        List<String> hosts = ptr.values();
        if (hosts.size() > 1) {
            b.atLeast(CheckStatus.WARN)
                    .evidence("PTR 레코드가 " + hosts.size() + "개 — 일부 수신 서버는 다중 PTR을 불신함")
                    .guidance("PTR은 발신 호스트명 하나만 남기는 것을 권장합니다");
        }

        boolean ipv6 = ip.contains(":");
        List<String> confirmed = new ArrayList<>();
        for (String host : hosts) {
            DnsAnswer forward = dns.query(host, ipv6 ? RecordType.AAAA : RecordType.A);
            if (forward.values().contains(ip)) {
                confirmed.add(host);
            } else {
                b.evidence("정방향 확인 실패: " + host + " → " +
                        (forward.hasRecords() ? String.join(", ", forward.values()) : "(A/AAAA 없음)")
                        + " ≠ " + ip);
            }
        }

        if (confirmed.isEmpty()) {
            b.status(CheckStatus.FAIL)
                    .guidance("PTR이 가리키는 호스트명의 A/AAAA 레코드가 원래 IP로 되돌아오도록 정/역방향을 맞추세요 (FCrDNS)");
        } else {
            confirmed.forEach(h -> b.evidence("FCrDNS 확인: " + ip + " → " + h + " → " + ip));
        }

        b.evidence("※ HELO/EHLO 명과 PTR 일치 여부는 SMTP 세션이 필요해 2단계(실메일 모드)에서 검사");
        return b.build();
    }
}
