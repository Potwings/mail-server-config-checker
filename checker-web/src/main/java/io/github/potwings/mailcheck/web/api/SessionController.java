package io.github.potwings.mailcheck.web.api;

import io.github.potwings.mailcheck.mail.session.DiagnosisSession;
import io.github.potwings.mailcheck.mail.session.MailResult;
import io.github.potwings.mailcheck.mail.session.SessionStore;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.time.Clock;
import java.time.Instant;
import java.util.List;

@RestController
@RequestMapping("/api/v1/sessions")
public class SessionController {

    private final SessionStore sessionStore;
    private final Clock clock;

    public SessionController(SessionStore sessionStore, Clock clock) {
        this.sessionStore = sessionStore;
        this.clock = clock;
    }

    /**
     * expired means only "새 메일은 더 이상 매칭되지 않음" — 이미 쌓인 결과는 계속 조회된다.
     */
    public record SessionResponse(String id, String address, Instant createdAt, Instant expiresAt,
                                  boolean expired, List<MailResult> mails) {

        static SessionResponse of(DiagnosisSession s, Instant now) {
            return new SessionResponse(s.id(), s.address(), s.createdAt(), s.expiresAt(),
                    s.expiredAt(now), s.mails());
        }
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public SessionResponse create() {
        return SessionResponse.of(sessionStore.create(), clock.instant());
    }

    @GetMapping("/{id}")
    public SessionResponse get(@PathVariable String id) {
        return sessionStore.find(id)
                .map(s -> SessionResponse.of(s, clock.instant()))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "세션을 찾을 수 없습니다"));
    }
}
