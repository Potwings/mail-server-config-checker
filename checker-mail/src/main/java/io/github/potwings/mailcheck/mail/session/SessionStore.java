package io.github.potwings.mailcheck.mail.session;

import java.util.Optional;

public interface SessionStore {

    /** Issues a new session with a fresh test address and persists it. */
    DiagnosisSession create();

    Optional<DiagnosisSession> find(String id);

    /** Resolves a rcpt local part ("check-{uuid}") to its session; empty when the token doesn't match. */
    Optional<DiagnosisSession> findByLocalPart(String localPart);

    /** @return false when the session does not exist */
    boolean appendResult(String id, MailResult result);
}
