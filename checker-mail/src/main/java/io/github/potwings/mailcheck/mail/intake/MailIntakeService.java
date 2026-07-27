package io.github.potwings.mailcheck.mail.intake;

import io.github.potwings.mailcheck.api.CheckContext;
import io.github.potwings.mailcheck.engine.CheckEngine;
import io.github.potwings.mailcheck.engine.DiagnosisReport;
import io.github.potwings.mailcheck.mail.eml.FromHeaderExtractor;
import io.github.potwings.mailcheck.mail.meta.MailMeta;
import io.github.potwings.mailcheck.mail.meta.MailMetaParser;
import io.github.potwings.mailcheck.mail.session.DiagnosisSession;
import io.github.potwings.mailcheck.mail.session.MailResult;
import io.github.potwings.mailcheck.mail.session.MailResultStatus;
import io.github.potwings.mailcheck.mail.session.SessionStore;
import io.github.potwings.mailcheck.mail.util.IpClassifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * Consumes the collector's incoming directories (infra-work.md §3) and turns
 * each mail into a session card. The incoming tree is read-only for us — no
 * delete/move; message.eml stays in place for M8 (DKIM 등) to re-read.
 *
 * <p>Decision ladder per directory: only transient IO errors return without
 * marking (retried next poll); every other outcome is marked processed exactly
 * once so a restart never re-diagnoses.
 */
public class MailIntakeService {

    private static final Logger log = LoggerFactory.getLogger(MailIntakeService.class);

    static final String PRIVATE_IP_NOTE =
            "이 메일은 내부망을 거쳐 도착해 발신 IP를 확인할 수 없습니다. "
                    + "진단 대상 서버와 다른 네트워크에서 다시 보내주세요.";
    static final String FROM_EXTRACT_FAILED_NOTE =
            "메일의 From 헤더에서 도메인을 추출하지 못해 진단을 실행할 수 없습니다. "
                    + "표준 형식의 From 헤더로 다시 보내주세요.";
    static final String ENGINE_FAILED_NOTE =
            "진단 실행 중 오류가 발생했습니다. 같은 주소로 테스트 메일을 다시 보내주세요.";

    private final Path incomingDir;
    private final MailMetaParser metaParser;
    private final FromHeaderExtractor fromExtractor;
    private final SessionStore sessionStore;
    private final ProcessedLog processedLog;
    private final CheckEngine engine;
    private final Clock clock;

    public MailIntakeService(Path incomingDir, MailMetaParser metaParser,
                             FromHeaderExtractor fromExtractor, SessionStore sessionStore,
                             ProcessedLog processedLog, CheckEngine engine, Clock clock) {
        this.incomingDir = incomingDir;
        this.metaParser = metaParser;
        this.fromExtractor = fromExtractor;
        this.sessionStore = sessionStore;
        this.processedLog = processedLog;
        this.engine = engine;
        this.clock = clock;
    }

    /** Never throws — one bad directory must not stop the poll loop. */
    public void pollOnce() {
        List<Path> candidates;
        try (Stream<Path> entries = Files.list(incomingDir)) {
            candidates = entries
                    .filter(Files::isDirectory)
                    // "." 시작 = 수집기가 아직 쓰는 중 (원자적 rename 계약, infra §3.2)
                    .filter(p -> !p.getFileName().toString().startsWith("."))
                    .filter(p -> !processedLog.contains(p.getFileName().toString()))
                    .sorted()
                    .toList();
        } catch (IOException e) {
            log.warn("수집 디렉터리 나열 실패: {}", incomingDir, e);
            return;
        }
        for (Path dir : candidates) {
            try {
                handle(dir);
            } catch (Exception e) {
                log.warn("수집물 처리 중 예기치 못한 오류 (다음 폴에 재시도): {}", dir, e);
            }
        }
    }

    private void handle(Path dir) throws IOException {
        String dirName = dir.getFileName().toString();

        MailMeta meta;
        try {
            meta = metaParser.parse(dir.resolve("meta.json"));
        } catch (MailIntakeException e) {
            log.warn("meta.json이 손상되어 건너뜀: {}", dirName, e);
            processedLog.markProcessed(dirName);
            return;
        } catch (IOException e) {
            log.debug("meta.json 읽기 실패 — 다음 폴에 재시도: {}", dirName, e);
            return;
        }

        Optional<DiagnosisSession> session = sessionStore.findByLocalPart(meta.rcptLocalPart());
        if (session.isEmpty()) {
            // catch-all이라 임의 수신자로도 메일이 들어온다 (RCPT 토큰 검증은 M6 잔여)
            log.info("발급된 토큰과 매칭되지 않는 수신자 — 진단하지 않음: {} ({})",
                    meta.rcptTo(), dirName);
            processedLog.markProcessed(dirName);
            return;
        }

        Instant receivedAt = meta.receivedAt() != null ? meta.receivedAt().toInstant() : clock.instant();
        if (session.get().expiredAt(receivedAt)) {
            log.info("세션 TTL 만료 후 도착한 메일 — 건너뜀: {} (세션 {})", dirName, session.get().id());
            processedLog.markProcessed(dirName);
            return;
        }

        MailResult result = diagnose(dir, meta);
        if (!sessionStore.appendResult(session.get().id(), result)) {
            log.warn("세션 파일이 사라져 결과를 기록하지 못함: {} ({})", session.get().id(), dirName);
        }
        processedLog.markProcessed(dirName);
    }

    private MailResult diagnose(Path dir, MailMeta meta) {
        String dirName = dir.getFileName().toString();

        if (IpClassifier.isNonPublic(meta.clientIp())) {
            return result(meta, dirName, null, MailResultStatus.REJECTED_PRIVATE_IP,
                    PRIVATE_IP_NOTE, null);
        }

        Optional<String> fromDomain = fromExtractor.extractFromDomain(dir.resolve("message.eml"));
        if (fromDomain.isEmpty()) {
            // 사용자가 결과 화면에서 대기 중이므로 침묵하지 않고 실패 카드를 남긴다
            return result(meta, dirName, null, MailResultStatus.FAILED,
                    FROM_EXTRACT_FAILED_NOTE, null);
        }

        try {
            CheckContext ctx = new CheckContext(fromDomain.get(), List.of(meta.clientIp()),
                    "SMTP 세션 접속 IP", true,
                    new CheckContext.MailSession(meta.mailFrom(), meta.helo()),
                    dir.resolve("message.eml"));
            DiagnosisReport report = engine.diagnose(ctx);
            return result(meta, dirName, fromDomain.get(), MailResultStatus.DIAGNOSED, null, report);
        } catch (Exception e) {
            log.warn("진단 엔진 실행 실패: {}", dirName, e);
            return result(meta, dirName, fromDomain.get(), MailResultStatus.FAILED,
                    ENGINE_FAILED_NOTE, null);
        }
    }

    private static MailResult result(MailMeta meta, String dirName, String fromDomain,
                                     MailResultStatus status, String note, DiagnosisReport report) {
        return new MailResult(meta.queueId(), dirName, meta.receivedAt(), meta.clientIp(),
                meta.helo(), meta.mailFrom(), fromDomain, status, note, report);
    }
}
