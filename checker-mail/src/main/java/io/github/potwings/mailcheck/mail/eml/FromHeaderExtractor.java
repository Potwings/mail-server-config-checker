package io.github.potwings.mailcheck.mail.eml;

import io.github.potwings.mailcheck.mail.util.Domains;
import org.apache.james.mime4j.codec.DecodeMonitor;
import org.apache.james.mime4j.dom.Message;
import org.apache.james.mime4j.dom.address.Mailbox;
import org.apache.james.mime4j.dom.address.MailboxList;
import org.apache.james.mime4j.message.DefaultMessageBuilder;
import org.apache.james.mime4j.stream.MimeConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

/**
 * Pulls the domain of the first From: mailbox out of message.eml using mime4j's
 * lenient parser (display names, quoted strings, folding, groups). Content
 * problems never throw — the caller renders a FAILED card from Optional.empty().
 */
public class FromHeaderExtractor {

    private static final Logger log = LoggerFactory.getLogger(FromHeaderExtractor.class);

    public Optional<String> extractFromDomain(Path emlFile) {
        try {
            byte[] headers = headerBlock(Files.readAllBytes(emlFile));
            DefaultMessageBuilder builder = new DefaultMessageBuilder();
            builder.setMimeEntityConfig(MimeConfig.PERMISSIVE);
            builder.setDecodeMonitor(DecodeMonitor.SILENT);
            try (InputStream in = new ByteArrayInputStream(headers)) {
                Message message = builder.parseMessage(in);
                MailboxList from = message.getFrom();
                if (from == null || from.isEmpty()) {
                    return Optional.empty();
                }
                Mailbox first = from.get(0);
                return Optional.ofNullable(Domains.normalize(first.getDomain()));
            }
        } catch (Exception e) {
            log.warn("From 헤더 추출 실패: {}", emlFile, e);
            return Optional.empty();
        }
    }

    /** Header section only — the body is irrelevant here and may be large. */
    private static byte[] headerBlock(byte[] bytes) {
        for (int i = 0; i + 1 < bytes.length; i++) {
            if (bytes[i] == '\n'
                    && (bytes[i + 1] == '\n' || (bytes[i + 1] == '\r' && i + 2 < bytes.length && bytes[i + 2] == '\n'))) {
                byte[] head = new byte[i + 1];
                System.arraycopy(bytes, 0, head, 0, i + 1);
                return head;
            }
        }
        return bytes;
    }
}
