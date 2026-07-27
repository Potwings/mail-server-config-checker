package io.github.potwings.mailcheck.mail.session;

import io.github.potwings.mailcheck.api.CheckResult;
import io.github.potwings.mailcheck.api.CheckStatus;
import io.github.potwings.mailcheck.engine.DiagnosisReport;
import io.github.potwings.mailcheck.mail.json.MailJson;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class FileSessionStoreTest {

    private static final Instant NOW = Instant.parse("2026-07-27T10:00:00Z");
    private static final Duration TTL = Duration.ofHours(24);

    @TempDir
    Path dataDir;

    private FileSessionStore store;

    @BeforeEach
    void setUp() throws IOException {
        store = newStore();
    }

    private FileSessionStore newStore() throws IOException {
        return new FileSessionStore(dataDir, "mail-check.example", TTL,
                MailJson.mapper(), Clock.fixed(NOW, ZoneOffset.UTC));
    }

    private static MailResult diagnosedResult() {
        DiagnosisReport report = new DiagnosisReport("example.com", List.of("203.0.113.50"),
                "SMTP 세션 접속 IP", 1234,
                List.of(CheckResult.builder("spf", "SPF").status(CheckStatus.PASS)
                        .evidence("레코드: v=spf1 -all").guidance("없음").build()));
        return new MailResult("Q1", "20260727T100000Z-Q1",
                OffsetDateTime.of(2026, 7, 27, 10, 0, 0, 0, ZoneOffset.UTC),
                "203.0.113.50", "mx.example.com", "test@example.com", "example.com",
                MailResultStatus.DIAGNOSED, null, report);
    }

    @Test
    void create는_토큰_주소와_TTL을_설정하고_파일로_보존() {
        DiagnosisSession s = store.create();

        assertThat(s.address()).isEqualTo("check-" + s.id() + "@mail-check.example");
        assertThat(s.createdAt()).isEqualTo(NOW);
        assertThat(s.expiresAt()).isEqualTo(NOW.plus(TTL));
        assertThat(dataDir.resolve("sessions").resolve(s.id() + ".json")).exists();
    }

    @Test
    void 결과_추가_후_재기동해도_전체_결과가_복원된다() throws IOException {
        DiagnosisSession s = store.create();
        assertThat(store.appendResult(s.id(), diagnosedResult())).isTrue();

        Optional<DiagnosisSession> reloaded = newStore().find(s.id());

        assertThat(reloaded).isPresent();
        assertThat(reloaded.get().mails()).hasSize(1);
        MailResult mail = reloaded.get().mails().get(0);
        assertThat(mail.status()).isEqualTo(MailResultStatus.DIAGNOSED);
        assertThat(mail.report().results()).hasSize(1);
        assertThat(mail.report().results().get(0).status()).isEqualTo(CheckStatus.PASS);
        assertThat(mail.report().results().get(0).evidence()).containsExactly("레코드: v=spf1 -all");
    }

    @Test
    void 없는_세션에_appendResult는_false() {
        assertThat(store.appendResult("00000000-0000-0000-0000-000000000000", diagnosedResult()))
                .isFalse();
    }

    @Test
    void findByLocalPart는_check_접두_uuid만_해석한다() {
        DiagnosisSession s = store.create();

        assertThat(store.findByLocalPart("check-" + s.id())).isPresent();
        assertThat(store.findByLocalPart("CHECK-" + s.id().toUpperCase())).isPresent();
        assertThat(store.findByLocalPart("admin")).isEmpty();
        assertThat(store.findByLocalPart("check-not-a-uuid")).isEmpty();
        assertThat(store.findByLocalPart("check-../../etc/passwd")).isEmpty();
        assertThat(store.findByLocalPart(null)).isEmpty();
    }

    @Test
    void 손상된_세션_파일은_없는_것으로_처리() throws IOException {
        DiagnosisSession s = store.create();
        Files.writeString(dataDir.resolve("sessions").resolve(s.id() + ".json"), "{ corrupt");

        assertThat(store.find(s.id())).isEmpty();
    }

    @Test
    void 존재하지_않는_id는_empty() {
        assertThat(store.find("11111111-2222-3333-4444-555555555555")).isEmpty();
        assertThat(store.find("not-a-uuid")).isEmpty();
    }
}
