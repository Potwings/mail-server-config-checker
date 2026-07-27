package io.github.potwings.mailcheck.mail.check.dkim;

import io.github.potwings.mailcheck.dns.DnsQueryService;
import org.apache.james.jdkim.DKIMVerifier;
import org.apache.james.jdkim.api.Result;
import org.apache.james.jdkim.exceptions.FailException;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;

/**
 * Runs jDKIM verification over message.eml and normalizes the outcome so both
 * the DKIM check and the DMARC alignment check share one verification pass
 * shape (each check still verifies independently — checks stay isolated).
 */
public class DkimVerificationSupport {

    /**
     * @param noSignature   the mail carries no DKIM-Signature header at all
     * @param results       per-signature pass/fail details (empty when noSignature/error)
     * @param passedDomains lowercase d= domains of signatures that verified
     * @param error         non-null when the message could not be processed at all
     */
    public record Outcome(boolean noSignature, List<Result> results,
                          List<String> passedDomains, String error) {
    }

    private final DnsQueryService dns;

    public DkimVerificationSupport(DnsQueryService dns) {
        this.dns = dns;
    }

    public Outcome verify(Path emlPath) {
        // jDKIM accumulates results per instance — use a fresh verifier per run.
        DKIMVerifier verifier = new DKIMVerifier(new DnsQueryServiceKeyRetriever(dns));
        try (InputStream in = new BufferedInputStream(Files.newInputStream(emlPath))) {
            verifier.verify(in);
        } catch (FailException e) {
            // 서명은 있으나 전부 실패 — 상세는 getResults()에 남아 있음
        } catch (IOException e) {
            return new Outcome(false, List.of(), List.of(), "message.eml 읽기 실패: " + e.getMessage());
        } catch (RuntimeException e) {
            return new Outcome(false, List.of(), List.of(), "DKIM 검증 중 오류: " + e.getMessage());
        }

        List<Result> results = verifier.getResults();
        if (results.isEmpty()) {
            return new Outcome(true, List.of(), List.of(), null);
        }
        List<String> passed = results.stream()
                .filter(Result::isSuccess)
                .filter(r -> r.getRecord() != null && r.getRecord().getDToken() != null)
                .map(r -> r.getRecord().getDToken().toString().toLowerCase(Locale.ROOT))
                .distinct()
                .toList();
        return new Outcome(false, results, passed, null);
    }
}
