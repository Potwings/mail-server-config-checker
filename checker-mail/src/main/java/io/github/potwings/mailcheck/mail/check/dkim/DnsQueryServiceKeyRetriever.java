package io.github.potwings.mailcheck.mail.check.dkim;

import io.github.potwings.mailcheck.dns.DnsAnswer;
import io.github.potwings.mailcheck.dns.DnsQueryService;
import io.github.potwings.mailcheck.dns.RecordType;
import org.apache.james.jdkim.api.PublicKeyRecordRetriever;
import org.apache.james.jdkim.exceptions.PermFailException;
import org.apache.james.jdkim.exceptions.TempFailException;

import java.util.List;

/**
 * jDKIM public-key lookup routed through {@link DnsQueryService} so DKIM
 * verification obeys the project rule that checks never touch the network
 * directly (unit tests mock the DNS layer).
 */
public class DnsQueryServiceKeyRetriever implements PublicKeyRecordRetriever {

    private final DnsQueryService dns;

    public DnsQueryServiceKeyRetriever(DnsQueryService dns) {
        this.dns = dns;
    }

    @Override
    public List<String> getRecords(CharSequence methodAndOption, CharSequence selector,
                                   CharSequence token) throws TempFailException, PermFailException {
        if (!"dns/txt".contentEquals(methodAndOption)) {
            throw new PermFailException("지원하지 않는 키 조회 방식: " + methodAndOption);
        }
        DnsAnswer ans = dns.query(selector + "._domainkey." + token, RecordType.TXT);
        if (ans.failed()) {
            throw new TempFailException("공개키 TXT 조회 실패 (" + ans.rcode() + "): "
                    + selector + "._domainkey." + token);
        }
        return ans.values();
    }
}
