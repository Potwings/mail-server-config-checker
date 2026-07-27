package io.github.potwings.mailcheck.mail.session;

/** Outcome of processing one received mail within a session. */
public enum MailResultStatus {
    /** Checks ran; a DiagnosisReport is attached. */
    DIAGNOSED,
    /** Client IP was private/non-public (hairpin NAT 등) — engine not run. */
    REJECTED_PRIVATE_IP,
    /** Mail arrived but could not be diagnosed (extraction/engine failure). */
    FAILED
}
