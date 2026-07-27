package io.github.potwings.mailcheck.mail.session;

import java.time.Instant;
import java.util.List;

/**
 * A diagnosis session: one issued test address plus the results of every mail
 * received on it. Persisted as {data-dir}/sessions/{id}.json.
 *
 * @param id      UUID; the mail token is "check-{id}" so the session file is
 *                derivable straight from the rcpt local part (no index needed)
 * @param address full test address shown to the user
 */
public record DiagnosisSession(String id, String address, Instant createdAt, Instant expiresAt,
                               List<MailResult> mails) {

    public DiagnosisSession {
        mails = mails == null ? List.of() : List.copyOf(mails);
    }

    public boolean expiredAt(Instant now) {
        return now.isAfter(expiresAt);
    }
}
