package io.github.potwings.mailcheck.mail.intake;

/**
 * Permanent failure while consuming a collected mail (schema mismatch, corrupt
 * content). Unlike an IOException this will not succeed on retry, so the caller
 * should mark the directory processed and move on.
 */
public class MailIntakeException extends RuntimeException {

    public MailIntakeException(String message, Throwable cause) {
        super(message, cause);
    }

    public MailIntakeException(String message) {
        super(message);
    }
}
