package io.github.potwings.mailcheck.check.mx;

import com.google.common.net.InetAddresses;
import io.github.potwings.mailcheck.api.Check;
import io.github.potwings.mailcheck.api.CheckContext;
import io.github.potwings.mailcheck.api.CheckResult;
import io.github.potwings.mailcheck.api.CheckStatus;
import io.github.potwings.mailcheck.dns.DnsAnswer;
import io.github.potwings.mailcheck.dns.DnsQueryService;
import io.github.potwings.mailcheck.dns.RecordType;
import io.github.potwings.mailcheck.net.IpRanges;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * MX presence/priority, resolvability of exchange hosts, and RFC violations:
 * MX pointing at a CNAME (RFC 5321 §5.1 / RFC 2181 §10.3) and Null MX (RFC 7505).
 */
public class MxCheck implements Check {

    private final DnsQueryService dns;

    public MxCheck(DnsQueryService dns) {
        this.dns = dns;
    }

    @Override
    public String id() {
        return "mx";
    }

    @Override
    public String title() {
        return "MX / DNS 배포";
    }

    private record MxEntry(int pref, String host) {
    }

    @Override
    public CheckResult run(CheckContext ctx) {
        CheckResult.Builder b = CheckResult.builder(id(), title());
        String domain = ctx.domain();

        DnsAnswer ans = dns.query(domain, RecordType.MX);
        if (ans.failed()) {
            return b.status(CheckStatus.ERROR).evidence("MX 조회 실패 (" + ans.rcode() + ")").build();
        }
        if (ans.isNxDomain()) {
            return b.status(CheckStatus.FAIL).evidence("도메인이 존재하지 않음 (NXDOMAIN)").build();
        }

        if (!ans.hasRecords()) {
            DnsAnswer a = dns.query(domain, RecordType.A);
            if (a.hasRecords()) {
                return b.status(CheckStatus.WARN)
                        .evidence("MX 레코드 없음 — A 레코드(" + String.join(", ", a.values())
                                + ")로 암묵적 MX 동작 (RFC 5321 §5.1)")
                        .guidance("명시적 MX 레코드를 추가하세요. 암묵적 MX 의존은 운영상 사고로 이어지기 쉽습니다")
                        .build();
            }
            return b.status(CheckStatus.FAIL)
                    .evidence("MX 레코드도 A 레코드도 없음 — 이 도메인으로 메일을 수신할 수 없음")
                    .guidance("수신 서버를 가리키는 MX 레코드를 추가하세요")
                    .build();
        }

        List<MxEntry> entries = new ArrayList<>();
        for (String v : ans.values()) {
            String[] parts = v.trim().split("\\s+", 2);
            if (parts.length == 2) {
                try {
                    entries.add(new MxEntry(Integer.parseInt(parts[0]), parts[1]));
                } catch (NumberFormatException ignored) {
                }
            }
        }
        entries.sort(Comparator.comparingInt(MxEntry::pref));

        if (entries.size() == 1 && (entries.get(0).host().equals(".") || entries.get(0).host().isEmpty())) {
            return b.status(CheckStatus.WARN)
                    .evidence("Null MX (RFC 7505) — 이 도메인은 메일을 받지 않는다고 선언함")
                    .guidance("메일 수신이 필요한 도메인이라면 Null MX를 실제 MX로 교체하세요")
                    .build();
        }

        int unresolved = 0;
        int resolvedIpCount = 0;
        int nonRoutableCount = 0;
        boolean anyIpLiteralMx = false;
        for (MxEntry e : entries) {
            if (InetAddresses.isInetAddress(e.host())) {
                anyIpLiteralMx = true;
                b.atLeast(CheckStatus.WARN)
                        .evidence("MX " + e.pref() + " " + e.host() + " — 호스트명이 아닌 IP 리터럴 (RFC 5321 §5.1 위반)");
                continue;
            }

            DnsAnswer cname = dns.query(e.host(), RecordType.CNAME);
            if (cname.hasRecords()) {
                b.atLeast(CheckStatus.WARN)
                        .evidence("MX " + e.host() + " 가 CNAME(" + cname.values().get(0)
                                + ") — RFC 5321 §5.1 / RFC 2181 §10.3 위반")
                        .guidance("MX 대상은 A/AAAA를 직접 가진 호스트명이어야 합니다. CNAME 대신 실제 호스트를 지정하세요");
            }

            DnsAnswer a = dns.query(e.host(), RecordType.A);
            DnsAnswer aaaa = dns.query(e.host(), RecordType.AAAA);
            List<String> ips = new ArrayList<>(a.values());
            ips.addAll(aaaa.values());
            if (ips.isEmpty()) {
                unresolved++;
                b.evidence("MX " + e.pref() + " " + e.host() + " → A/AAAA 해석 불가");
            } else {
                b.evidence("MX " + e.pref() + " " + e.host() + " → " + String.join(", ", ips));
                for (String ip : ips) {
                    resolvedIpCount++;
                    String reason = IpRanges.nonRoutableReason(ip);
                    if (reason != null) {
                        nonRoutableCount++;
                        b.atLeast(CheckStatus.WARN)
                                .evidence("MX " + e.host() + " 의 " + ip + " 는 공인 IP가 아님 — " + reason);
                    }
                }
            }
        }

        if (unresolved == entries.size()) {
            b.status(CheckStatus.FAIL)
                    .guidance("모든 MX 호스트가 IP로 해석되지 않아 메일 수신이 불가능합니다");
        } else if (unresolved > 0) {
            b.atLeast(CheckStatus.WARN)
                    .guidance("해석되지 않는 MX 호스트를 제거하거나 A/AAAA 레코드를 추가하세요");
        }

        if (anyIpLiteralMx) {
            b.guidance("MX 대상은 A/AAAA 레코드를 가진 호스트명이어야 합니다 — IP 리터럴 대신 호스트명을 지정하세요");
        }
        if (nonRoutableCount > 0) {
            if (nonRoutableCount == resolvedIpCount) {
                b.status(CheckStatus.FAIL)
                        .guidance("모든 MX가 사설/예약 IP로만 해석되어 인터넷에서 메일을 수신할 수 없습니다 — "
                                + "내부용(스플릿 DNS) 존이 외부에 노출된 구성인지 확인하세요");
            } else {
                b.guidance("사설/예약 IP로 해석되는 MX는 외부 발신자가 접근할 수 없습니다 — 공인 IP를 가리키도록 수정하세요");
            }
        }

        if (entries.size() == 1) {
            b.evidence("MX가 1개 — 백업 MX 구성(우선순위 분리)을 고려할 수 있음");
        }

        return b.build();
    }
}
