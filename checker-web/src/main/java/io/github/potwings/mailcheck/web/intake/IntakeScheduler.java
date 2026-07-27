package io.github.potwings.mailcheck.web.intake;

import io.github.potwings.mailcheck.mail.intake.MailIntakeService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnProperty(prefix = "mailcheck.intake", name = "enabled", havingValue = "true")
public class IntakeScheduler {

    private static final Logger log = LoggerFactory.getLogger(IntakeScheduler.class);

    private final MailIntakeService intakeService;

    public IntakeScheduler(MailIntakeService intakeService) {
        this.intakeService = intakeService;
    }

    @Scheduled(fixedDelayString = "${mailcheck.intake.poll-interval:5s}")
    public void poll() {
        try {
            intakeService.pollOnce();
        } catch (Exception e) {
            // pollOnce는 throw하지 않는 계약이지만, 스케줄 스레드가 죽으면 폴링이 멈추므로 이중 방어
            log.error("인테이크 폴링 실패", e);
        }
    }
}
