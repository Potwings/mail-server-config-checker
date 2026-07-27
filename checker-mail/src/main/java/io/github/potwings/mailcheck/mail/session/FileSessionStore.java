package io.github.potwings.mailcheck.mail.session;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;

/**
 * File-per-session JSON store. Restart durability is the point: no DB, files
 * survive the process. Writes go through a temp file + ATOMIC_MOVE so a crash
 * never leaves a half-written session behind; a corrupt file is logged and
 * treated as absent instead of poisoning the whole store.
 */
public class FileSessionStore implements SessionStore {

    private static final Logger log = LoggerFactory.getLogger(FileSessionStore.class);
    private static final String TOKEN_PREFIX = "check-";

    private final Path sessionsDir;
    private final String mailDomain;
    private final Duration ttl;
    private final ObjectMapper mapper;
    private final Clock clock;

    public FileSessionStore(Path dataDir, String mailDomain, Duration ttl,
                            ObjectMapper mapper, Clock clock) throws IOException {
        this.sessionsDir = dataDir.resolve("sessions");
        this.mailDomain = mailDomain;
        this.ttl = ttl;
        this.mapper = mapper;
        this.clock = clock;
        Files.createDirectories(sessionsDir);
    }

    @Override
    public synchronized DiagnosisSession create() {
        String id = UUID.randomUUID().toString();
        Instant now = clock.instant();
        DiagnosisSession session = new DiagnosisSession(id, TOKEN_PREFIX + id + "@" + mailDomain,
                now, now.plus(ttl), List.of());
        write(session);
        return session;
    }

    @Override
    public synchronized Optional<DiagnosisSession> find(String id) {
        String normalized = normalizeId(id);
        if (normalized == null) {
            return Optional.empty();
        }
        Path file = sessionsDir.resolve(normalized + ".json");
        if (!Files.exists(file)) {
            return Optional.empty();
        }
        try {
            return Optional.of(mapper.readValue(file.toFile(), DiagnosisSession.class));
        } catch (IOException e) {
            log.warn("세션 파일 손상 — 없는 것으로 처리: {}", file, e);
            return Optional.empty();
        }
    }

    @Override
    public synchronized Optional<DiagnosisSession> findByLocalPart(String localPart) {
        if (localPart == null || !localPart.toLowerCase(Locale.ROOT).startsWith(TOKEN_PREFIX)) {
            return Optional.empty();
        }
        return find(localPart.substring(TOKEN_PREFIX.length()));
    }

    @Override
    public synchronized boolean appendResult(String id, MailResult result) {
        Optional<DiagnosisSession> found = find(id);
        if (found.isEmpty()) {
            return false;
        }
        DiagnosisSession s = found.get();
        List<MailResult> mails = new ArrayList<>(s.mails());
        mails.add(result);
        write(new DiagnosisSession(s.id(), s.address(), s.createdAt(), s.expiresAt(), mails));
        return true;
    }

    /** @return the canonical lowercase UUID, or null when the input is not one (path-safe gate) */
    private static String normalizeId(String id) {
        if (id == null) {
            return null;
        }
        try {
            return UUID.fromString(id.trim().toLowerCase(Locale.ROOT)).toString();
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private void write(DiagnosisSession session) {
        Path target = sessionsDir.resolve(session.id() + ".json");
        Path temp = sessionsDir.resolve(".tmp-" + session.id() + ".json");
        try {
            mapper.writerWithDefaultPrettyPrinter().writeValue(temp.toFile(), session);
            Files.move(temp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            throw new UncheckedIOException("세션 파일 쓰기 실패: " + target, e);
        }
    }
}
