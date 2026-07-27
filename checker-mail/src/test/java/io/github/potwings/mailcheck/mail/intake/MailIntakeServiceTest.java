package io.github.potwings.mailcheck.mail.intake;

import io.github.potwings.mailcheck.api.CheckContext;
import io.github.potwings.mailcheck.engine.CheckEngine;
import io.github.potwings.mailcheck.engine.DiagnosisReport;
import io.github.potwings.mailcheck.mail.eml.FromHeaderExtractor;
import io.github.potwings.mailcheck.mail.json.MailJson;
import io.github.potwings.mailcheck.mail.meta.MailMetaParser;
import io.github.potwings.mailcheck.mail.session.DiagnosisSession;
import io.github.potwings.mailcheck.mail.session.FileSessionStore;
import io.github.potwings.mailcheck.mail.session.MailResult;
import io.github.potwings.mailcheck.mail.session.MailResultStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class MailIntakeServiceTest {

    private static final Instant NOW = Instant.parse("2026-07-27T10:00:00Z");

    @TempDir
    Path root;

    private Path incoming;
    private FileSessionStore store;
    private ProcessedLog processedLog;
    private CheckEngine engine;
    private MailIntakeService service;
    private DiagnosisSession session;

    @BeforeEach
    void setUp() throws IOException {
        incoming = root.resolve("incoming");
        Files.createDirectories(incoming);
        store = new FileSessionStore(root.resolve("data"), "mail-check.example",
                Duration.ofHours(24), MailJson.mapper(), Clock.fixed(NOW, ZoneOffset.UTC));
        processedLog = new ProcessedLog(root.resolve("data").resolve("processed.log"));
        engine = mock(CheckEngine.class);
        when(engine.diagnose(any())).thenReturn(
                new DiagnosisReport("example.com", List.of("203.0.113.50"), "SMTP 세션 접속 IP", 10, List.of()));
        service = new MailIntakeService(incoming, new MailMetaParser(), new FromHeaderExtractor(),
                store, processedLog, engine, Clock.fixed(NOW, ZoneOffset.UTC));
        session = store.create();
    }

    private String token() {
        return "check-" + session.id();
    }

    private Path mailDir(String name, String metaJson, String eml) throws IOException {
        Path dir = incoming.resolve(name);
        Files.createDirectories(dir);
        if (metaJson != null) {
            Files.writeString(dir.resolve("meta.json"), metaJson);
        }
        if (eml != null) {
            Files.writeString(dir.resolve("message.eml"), eml);
        }
        return dir;
    }

    private String meta(String clientIp, String mailFrom, String rcptTo, String receivedAt) {
        return """
                {
                  "received_at": "%s",
                  "queue_id": "Q1",
                  "client_ip": "%s",
                  "helo": "mx.example.com",
                  "mail_from": "%s",
                  "rcpt_to": "%s"
                }
                """.formatted(receivedAt, clientIp, mailFrom, rcptTo);
    }

    private static final String EML = """
            From: sender@example.com
            Subject: test

            body
            """;

    private List<MailResult> mails() {
        return store.find(session.id()).orElseThrow().mails();
    }

    @Test
    void 정상_메일은_세션값이_담긴_컨텍스트로_진단되고_DIAGNOSED_카드가_남는다() throws IOException {
        mailDir("20260727T095900Z-Q1",
                meta("203.0.113.50", "env@sender.example", token() + "@mail-check.example",
                        "2026-07-27T09:59:00+00:00"), EML);

        service.pollOnce();

        ArgumentCaptor<CheckContext> ctx = ArgumentCaptor.forClass(CheckContext.class);
        verify(engine).diagnose(ctx.capture());
        assertThat(ctx.getValue().domain()).isEqualTo("example.com");
        assertThat(ctx.getValue().targetIps()).containsExactly("203.0.113.50");
        assertThat(ctx.getValue().ipsUserProvided()).isTrue();
        assertThat(ctx.getValue().mailSession().mailFrom()).isEqualTo("env@sender.example");
        assertThat(ctx.getValue().mailSession().helo()).isEqualTo("mx.example.com");

        assertThat(mails()).hasSize(1);
        MailResult r = mails().get(0);
        assertThat(r.status()).isEqualTo(MailResultStatus.DIAGNOSED);
        assertThat(r.report()).isNotNull();
        assertThat(r.incomingDir()).isEqualTo("20260727T095900Z-Q1");
        assertThat(processedLog.contains("20260727T095900Z-Q1")).isTrue();
    }

    @Test
    void bounce_메일도_MailSession에_빈_mailFrom으로_전달된다() throws IOException {
        mailDir("20260727T095900Z-Q1",
                meta("203.0.113.50", "", token() + "@mail-check.example",
                        "2026-07-27T09:59:00+00:00"), EML);

        service.pollOnce();

        ArgumentCaptor<CheckContext> ctx = ArgumentCaptor.forClass(CheckContext.class);
        verify(engine).diagnose(ctx.capture());
        assertThat(ctx.getValue().mailSession().bounce()).isTrue();
    }

    @Test
    void 닷_디렉터리와_기처리_디렉터리는_무시한다() throws IOException {
        mailDir(".tmp-writing",
                meta("203.0.113.50", "a@b.example", token() + "@mail-check.example",
                        "2026-07-27T09:59:00+00:00"), EML);
        mailDir("20260727T095800Z-OLD",
                meta("203.0.113.50", "a@example.com", token() + "@mail-check.example",
                        "2026-07-27T09:58:00+00:00"), EML);
        processedLog.markProcessed("20260727T095800Z-OLD");

        service.pollOnce();

        verify(engine, never()).diagnose(any());
        assertThat(mails()).isEmpty();
    }

    @Test
    void 미매칭_토큰은_진단_없이_기처리로_기록된다() throws IOException {
        mailDir("20260727T095900Z-SPAM",
                meta("203.0.113.50", "spam@spam.example", "random-user@mail-check.example",
                        "2026-07-27T09:59:00+00:00"), EML);

        service.pollOnce();

        verify(engine, never()).diagnose(any());
        assertThat(mails()).isEmpty();
        assertThat(processedLog.contains("20260727T095900Z-SPAM")).isTrue();
    }

    @Test
    void TTL_만료_후_도착한_메일은_카드_없이_스킵된다() throws IOException {
        mailDir("20260729T120000Z-LATE",
                meta("203.0.113.50", "a@example.com", token() + "@mail-check.example",
                        "2026-07-29T12:00:00+00:00"), EML);

        service.pollOnce();

        verify(engine, never()).diagnose(any());
        assertThat(mails()).isEmpty();
        assertThat(processedLog.contains("20260729T120000Z-LATE")).isTrue();
    }

    @Test
    void 사설_IP는_엔진을_실행하지_않고_REJECTED_카드를_남긴다() throws IOException {
        mailDir("20260727T095900Z-NAT",
                meta("172.30.1.254", "a@example.com", token() + "@mail-check.example",
                        "2026-07-27T09:59:00+00:00"), EML);

        service.pollOnce();

        verify(engine, never()).diagnose(any());
        assertThat(mails()).hasSize(1);
        MailResult r = mails().get(0);
        assertThat(r.status()).isEqualTo(MailResultStatus.REJECTED_PRIVATE_IP);
        assertThat(r.note()).contains("내부망");
        assertThat(r.report()).isNull();
    }

    @Test
    void From_도메인_추출_실패는_FAILED_카드를_남긴다() throws IOException {
        mailDir("20260727T095900Z-NOFROM",
                meta("203.0.113.50", "a@example.com", token() + "@mail-check.example",
                        "2026-07-27T09:59:00+00:00"),
                "Subject: no from\n\nbody\n");

        service.pollOnce();

        verify(engine, never()).diagnose(any());
        assertThat(mails()).hasSize(1);
        assertThat(mails().get(0).status()).isEqualTo(MailResultStatus.FAILED);
    }

    @Test
    void 엔진_예외는_FAILED_카드로_변환된다() throws IOException {
        when(engine.diagnose(any())).thenThrow(new RuntimeException("boom"));
        mailDir("20260727T095900Z-ERR",
                meta("203.0.113.50", "a@example.com", token() + "@mail-check.example",
                        "2026-07-27T09:59:00+00:00"), EML);

        service.pollOnce();

        assertThat(mails()).hasSize(1);
        assertThat(mails().get(0).status()).isEqualTo(MailResultStatus.FAILED);
        assertThat(processedLog.contains("20260727T095900Z-ERR")).isTrue();
    }

    @Test
    void 손상된_meta는_영구_스킵되고_없는_meta는_재시도_대상으로_남는다() throws IOException {
        Path corrupt = mailDir("20260727T095900Z-BAD", "{ not json", EML);
        Path missing = mailDir("20260727T095901Z-MISSING", null, EML);

        service.pollOnce();

        verify(engine, never()).diagnose(any());
        assertThat(processedLog.contains(corrupt.getFileName().toString())).isTrue();
        assertThat(processedLog.contains(missing.getFileName().toString())).isFalse();
    }

    @Test
    void 한_건이_실패해도_다음_건은_처리된다() throws IOException {
        mailDir("20260727T095900Z-BAD", "{ not json", EML);
        mailDir("20260727T095901Z-OK",
                meta("203.0.113.50", "a@example.com", token() + "@mail-check.example",
                        "2026-07-27T09:59:01+00:00"), EML);

        service.pollOnce();

        verify(engine).diagnose(any());
        assertThat(mails()).hasSize(1);
    }
}
