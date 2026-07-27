package io.github.potwings.mailcheck.mail.session;

import io.github.potwings.mailcheck.engine.DiagnosisReport;

import java.time.OffsetDateTime;

/**
 * One received mail's processing outcome, embedded in the session file.
 *
 * @param incomingDir collector directory name — kept so M8 (DKIM 등) can re-read
 *                    the preserved message.eml
 * @param note        user-facing explanation for non-DIAGNOSED statuses
 * @param report      present only when status == DIAGNOSED
 */
public record MailResult(String queueId, String incomingDir, OffsetDateTime receivedAt,
                         String clientIp, String helo, String mailFrom, String fromDomain,
                         MailResultStatus status, String note, DiagnosisReport report) {
}
