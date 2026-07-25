package io.github.potwings.mailcheck.web.api;

import io.github.potwings.mailcheck.api.CheckContext;
import io.github.potwings.mailcheck.engine.CheckEngine;
import io.github.potwings.mailcheck.engine.DiagnosisReport;
import io.github.potwings.mailcheck.engine.TargetIpResolver;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/v1")
public class DiagnoseController {

    private final CheckEngine engine;
    private final TargetIpResolver targetIpResolver;

    public DiagnoseController(CheckEngine engine, TargetIpResolver targetIpResolver) {
        this.engine = engine;
        this.targetIpResolver = targetIpResolver;
    }

    @GetMapping("/diagnose")
    public DiagnosisReport diagnose(@RequestParam String domain,
                                    @RequestParam(required = false) String ip) {
        String normalizedDomain = InputValidator.normalizeDomain(domain);
        List<String> normalizedIps = InputValidator.normalizeIps(ip);

        CheckContext ctx = targetIpResolver.resolve(normalizedDomain, normalizedIps)
                .map(t -> new CheckContext(normalizedDomain, t.ips(), t.source()))
                .orElseGet(() -> new CheckContext(normalizedDomain, List.of(), null));
        return engine.diagnose(ctx);
    }
}
