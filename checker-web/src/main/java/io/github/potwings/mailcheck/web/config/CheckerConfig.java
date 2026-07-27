package io.github.potwings.mailcheck.web.config;

import io.github.potwings.mailcheck.api.Check;
import io.github.potwings.mailcheck.check.dmarc.DmarcCheck;
import io.github.potwings.mailcheck.check.dmarc.OrgDomainResolver;
import io.github.potwings.mailcheck.check.mx.MxCheck;
import io.github.potwings.mailcheck.check.propagation.DnsPropagationCheck;
import io.github.potwings.mailcheck.check.propagation.ResolverEndpoint;
import io.github.potwings.mailcheck.check.ptr.PtrCheck;
import io.github.potwings.mailcheck.check.rbl.BarracudaProvider;
import io.github.potwings.mailcheck.check.rbl.DomainRblCheck;
import io.github.potwings.mailcheck.check.rbl.HostkarmaProvider;
import io.github.potwings.mailcheck.check.rbl.MailspikeProvider;
import io.github.potwings.mailcheck.check.rbl.PsblProvider;
import io.github.potwings.mailcheck.check.rbl.RblCheck;
import io.github.potwings.mailcheck.check.rbl.RblProvider;
import io.github.potwings.mailcheck.check.rbl.SpamCopProvider;
import io.github.potwings.mailcheck.check.rbl.SpamhausDblProvider;
import io.github.potwings.mailcheck.check.rbl.SpamhausZenDqsProvider;
import io.github.potwings.mailcheck.check.spf.SpfCheck;
import io.github.potwings.mailcheck.check.tlspolicy.HttpPolicyFetcher;
import io.github.potwings.mailcheck.check.tlspolicy.TlsPolicyCheck;
import io.github.potwings.mailcheck.dns.DnsJavaQueryService;
import io.github.potwings.mailcheck.dns.DnsQueryService;
import io.github.potwings.mailcheck.engine.CheckEngine;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Configuration
public class CheckerConfig {

    @Bean
    public DnsQueryService dnsQueryService(MailcheckProperties props) {
        return new DnsJavaQueryService(props.dnsTimeout());
    }

    @Bean
    public OrgDomainResolver orgDomainResolver() {
        return new OrgDomainResolver();
    }

    @Bean
    public SpfCheck spfCheck(DnsQueryService dns) {
        return new SpfCheck(dns);
    }

    @Bean
    public DmarcCheck dmarcCheck(DnsQueryService dns, OrgDomainResolver orgResolver) {
        return new DmarcCheck(dns, orgResolver);
    }

    @Bean
    public MxCheck mxCheck(DnsQueryService dns) {
        return new MxCheck(dns);
    }

    @Bean
    public PtrCheck ptrCheck(DnsQueryService dns) {
        return new PtrCheck(dns);
    }

    @Bean
    public RblCheck rblCheck(DnsQueryService dns, MailcheckProperties props) {
        List<RblProvider> providers = List.of(
                new SpamhausZenDqsProvider(props.rbl().spamhausDqsKey()),
                new BarracudaProvider(props.rbl().barracudaEnabled()),
                new SpamCopProvider(props.rbl().spamcopEnabled()),
                new PsblProvider(props.rbl().psblEnabled()),
                new MailspikeProvider(props.rbl().mailspikeEnabled()),
                new HostkarmaProvider(props.rbl().hostkarmaEnabled()));
        return new RblCheck(dns, providers);
    }

    @Bean
    public DomainRblCheck domainRblCheck(DnsQueryService dns, MailcheckProperties props) {
        return new DomainRblCheck(dns, List.of(new SpamhausDblProvider(props.rbl().spamhausDqsKey())));
    }

    @Bean
    public TlsPolicyCheck tlsPolicyCheck(DnsQueryService dns, MailcheckProperties props) {
        Duration timeout = props.mtaStsHttpTimeout() != null ? props.mtaStsHttpTimeout() : Duration.ofSeconds(5);
        return new TlsPolicyCheck(dns, new HttpPolicyFetcher(timeout));
    }

    @Bean
    public DnsPropagationCheck dnsPropagationCheck(DnsQueryService dns, MailcheckProperties props,
                                                   OrgDomainResolver orgResolver) {
        List<ResolverEndpoint> endpoints = props.propagationResolvers().stream()
                .map(ResolverEndpoint::parse)
                .toList();
        return new DnsPropagationCheck(dns, endpoints, orgResolver);
    }

    @Bean(destroyMethod = "shutdown")
    public ExecutorService checkExecutor() {
        return Executors.newFixedThreadPool(12);
    }

    @Bean
    public CheckEngine checkEngine(List<Check> checks, MailcheckProperties props, ExecutorService checkExecutor) {
        return new CheckEngine(checks, props.checkTimeout(), checkExecutor);
    }
}
