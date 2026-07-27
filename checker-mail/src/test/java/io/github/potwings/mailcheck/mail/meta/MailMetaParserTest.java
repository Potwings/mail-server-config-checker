package io.github.potwings.mailcheck.mail.meta;

import io.github.potwings.mailcheck.mail.intake.MailIntakeException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class MailMetaParserTest {

    @TempDir
    Path dir;

    private final MailMetaParser parser = new MailMetaParser();

    private Path write(String json) throws IOException {
        Path f = dir.resolve("meta.json");
        Files.writeString(f, json);
        return f;
    }

    @Test
    void 정상_meta를_파싱한다() throws IOException {
        MailMeta meta = parser.parse(write("""
                {
                  "received_at": "2026-07-26T10:12:26.972133+00:00",
                  "queue_id": "C51241200F0",
                  "client_ip": "203.0.113.50",
                  "client_hostname": "mx.example.com",
                  "client_port": "35850",
                  "client_protocol": "ESMTP",
                  "helo": "mx.example.com",
                  "mail_from": "test@example.com",
                  "rcpt_to": "check-1234@mail-check.example",
                  "original_rcpt_to": "check-1234@mail-check.example",
                  "size_reported": "673",
                  "size_actual": 621
                }
                """));

        assertThat(meta.queueId()).isEqualTo("C51241200F0");
        assertThat(meta.clientIp()).isEqualTo("203.0.113.50");
        assertThat(meta.mailFrom()).isEqualTo("test@example.com");
        assertThat(meta.receivedAt().getYear()).isEqualTo(2026);
        assertThat(meta.rcptLocalPart()).isEqualTo("check-1234");
    }

    @Test
    void 미지의_필드는_무시한다() throws IOException {
        MailMeta meta = parser.parse(write("""
                {"queue_id": "Q1", "client_ip": "203.0.113.50", "future_field": {"a": 1}}
                """));

        assertThat(meta.queueId()).isEqualTo("Q1");
    }

    @Test
    void 손상된_JSON은_영구_오류로_구분한다() throws IOException {
        Path f = write("{ not json");

        assertThatThrownBy(() -> parser.parse(f)).isInstanceOf(MailIntakeException.class);
    }

    @Test
    void 파일이_없으면_IOException_전파() {
        assertThatThrownBy(() -> parser.parse(dir.resolve("missing.json")))
                .isInstanceOf(IOException.class)
                .isNotInstanceOf(MailIntakeException.class);
    }

    @Test
    void rcptLocalPart는_대문자와_at_없는_주소를_처리() {
        assertThat(meta("Check-ABC@mail-check.example").rcptLocalPart()).isEqualTo("check-abc");
        assertThat(meta("noat").rcptLocalPart()).isNull();
        assertThat(meta(null).rcptLocalPart()).isNull();
    }

    private static MailMeta meta(String rcptTo) {
        return new MailMeta(null, "Q", "203.0.113.1", null, null, null, null, null,
                rcptTo, rcptTo, null, null);
    }
}
