package io.github.potwings.mailcheck.web.config;

import io.github.potwings.mailcheck.check.dmarc.OrgDomainResolver;
import io.github.potwings.mailcheck.dns.DnsQueryService;
import io.github.potwings.mailcheck.engine.CheckEngine;
import io.github.potwings.mailcheck.mail.check.dkim.DkimCheck;
import io.github.potwings.mailcheck.mail.check.dmarc.DmarcAlignmentCheck;
import io.github.potwings.mailcheck.mail.check.header.HeaderQualityCheck;
import io.github.potwings.mailcheck.mail.eml.FromHeaderExtractor;
import io.github.potwings.mailcheck.mail.intake.MailIntakeService;
import io.github.potwings.mailcheck.mail.intake.ProcessedLog;
import io.github.potwings.mailcheck.mail.json.MailJson;
import io.github.potwings.mailcheck.mail.meta.MailMetaParser;
import io.github.potwings.mailcheck.mail.session.FileSessionStore;
import io.github.potwings.mailcheck.mail.session.SessionStore;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Clock;

/** Wires the real-mail pipeline (checker-mail) — assembly only, no logic here. */
@Configuration
@EnableScheduling
public class MailPipelineConfig {

    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }

    @Bean
    public MailMetaParser mailMetaParser() {
        return new MailMetaParser();
    }

    @Bean
    public FromHeaderExtractor fromHeaderExtractor() {
        return new FromHeaderExtractor();
    }

    // 실메일 원문(message.eml)이 있어야 동작하는 검사들 — 엔진에는 다른 Check와 동일하게 수집됨
    @Bean
    public DkimCheck dkimCheck(DnsQueryService dns) {
        return new DkimCheck(dns);
    }

    @Bean
    public DmarcAlignmentCheck dmarcAlignmentCheck(DnsQueryService dns, OrgDomainResolver orgResolver) {
        return new DmarcAlignmentCheck(dns, orgResolver);
    }

    @Bean
    public HeaderQualityCheck headerQualityCheck() {
        return new HeaderQualityCheck();
    }

    @Bean
    public SessionStore sessionStore(MailcheckProperties props, Clock clock) throws IOException {
        MailcheckProperties.Intake intake = props.intake();
        return new FileSessionStore(Path.of(intake.dataDir()), intake.mailDomain(),
                intake.sessionTtl(), MailJson.mapper(), clock);
    }

    @Bean
    public ProcessedLog processedLog(MailcheckProperties props) throws IOException {
        return new ProcessedLog(Path.of(props.intake().dataDir(), "processed.log"));
    }

    @Bean
    public MailIntakeService mailIntakeService(MailcheckProperties props, MailMetaParser metaParser,
                                               FromHeaderExtractor fromExtractor, SessionStore sessionStore,
                                               ProcessedLog processedLog, CheckEngine engine, Clock clock) {
        return new MailIntakeService(Path.of(props.intake().incomingDir()), metaParser,
                fromExtractor, sessionStore, processedLog, engine, clock);
    }
}
