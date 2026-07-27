package io.github.potwings.mailcheck.web.api;

import io.github.potwings.mailcheck.api.CheckResult;
import io.github.potwings.mailcheck.api.CheckStatus;
import io.github.potwings.mailcheck.engine.DiagnosisReport;
import io.github.potwings.mailcheck.mail.session.DiagnosisSession;
import io.github.potwings.mailcheck.mail.session.MailResult;
import io.github.potwings.mailcheck.mail.session.MailResultStatus;
import io.github.potwings.mailcheck.mail.session.SessionStore;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Clock;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(SessionController.class)
class SessionControllerTest {

    private static final Instant NOW = Instant.parse("2026-07-27T10:00:00Z");
    private static final String ID = "11111111-2222-3333-4444-555555555555";

    @Autowired
    MockMvc mvc;

    @MockitoBean
    SessionStore sessionStore;

    @MockitoBean
    Clock clock;

    private void fixClock() {
        when(clock.instant()).thenReturn(NOW);
    }

    @Test
    void POST는_201과_토큰_주소를_반환한다() throws Exception {
        fixClock();
        when(sessionStore.create()).thenReturn(new DiagnosisSession(ID,
                "check-" + ID + "@mail-check.example", NOW, NOW.plusSeconds(86400), List.of()));

        mvc.perform(post("/api/v1/sessions"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").value(ID))
                .andExpect(jsonPath("$.address").value("check-" + ID + "@mail-check.example"))
                .andExpect(jsonPath("$.expired").value(false))
                .andExpect(jsonPath("$.mails").isEmpty());
    }

    @Test
    void GET은_DIAGNOSED와_REJECTED_카드를_함께_반환한다() throws Exception {
        fixClock();
        OffsetDateTime received = OffsetDateTime.of(2026, 7, 27, 9, 59, 0, 0, ZoneOffset.UTC);
        MailResult diagnosed = new MailResult("Q1", "20260727T095900Z-Q1", received,
                "203.0.113.50", "mx.example.com", "a@example.com", "example.com",
                MailResultStatus.DIAGNOSED, null,
                new DiagnosisReport("example.com", List.of("203.0.113.50"), "SMTP 세션 접속 IP", 10,
                        List.of(CheckResult.builder("spf", "SPF").status(CheckStatus.PASS).build())));
        MailResult rejected = new MailResult("Q2", "20260727T100100Z-Q2", received,
                "172.30.1.254", "internal", "a@example.com", null,
                MailResultStatus.REJECTED_PRIVATE_IP, "내부망 안내", null);
        when(sessionStore.find(ID)).thenReturn(Optional.of(new DiagnosisSession(ID,
                "check-" + ID + "@mail-check.example", NOW, NOW.plusSeconds(86400),
                List.of(diagnosed, rejected))));

        mvc.perform(get("/api/v1/sessions/{id}", ID))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.mails.length()").value(2))
                .andExpect(jsonPath("$.mails[0].status").value("DIAGNOSED"))
                .andExpect(jsonPath("$.mails[0].report.results[0].checkId").value("spf"))
                .andExpect(jsonPath("$.mails[1].status").value("REJECTED_PRIVATE_IP"))
                .andExpect(jsonPath("$.mails[1].note").value("내부망 안내"))
                .andExpect(jsonPath("$.mails[1].report").doesNotExist());
    }

    @Test
    void 만료된_세션은_expired_true로_응답한다() throws Exception {
        fixClock();
        when(sessionStore.find(ID)).thenReturn(Optional.of(new DiagnosisSession(ID,
                "check-" + ID + "@mail-check.example", NOW.minusSeconds(90000),
                NOW.minusSeconds(3600), List.of())));

        mvc.perform(get("/api/v1/sessions/{id}", ID))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.expired").value(true));
    }

    @Test
    void 없는_세션은_404와_error_본문() throws Exception {
        fixClock();
        when(sessionStore.find(anyString())).thenReturn(Optional.empty());

        mvc.perform(get("/api/v1/sessions/{id}", "unknown"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("세션을 찾을 수 없습니다"));
    }
}
