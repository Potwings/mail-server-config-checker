package io.github.potwings.mailcheck.engine;

import io.github.potwings.mailcheck.api.Check;
import io.github.potwings.mailcheck.api.CheckContext;
import io.github.potwings.mailcheck.api.CheckResult;
import io.github.potwings.mailcheck.api.CheckStatus;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Runs all checks concurrently with a per-check timeout so one slow check
 * can never stall the whole diagnosis.
 */
public class CheckEngine {

    private final List<Check> checks;
    private final Duration perCheckTimeout;
    private final ExecutorService executor;

    public CheckEngine(List<Check> checks, Duration perCheckTimeout, ExecutorService executor) {
        this.checks = List.copyOf(checks);
        this.perCheckTimeout = perCheckTimeout;
        this.executor = executor;
    }

    public DiagnosisReport diagnose(CheckContext ctx) {
        long start = System.nanoTime();

        List<CompletableFuture<CheckResult>> futures = checks.stream()
                .map(check -> CompletableFuture
                        .supplyAsync(() -> runTimed(check, ctx), executor)
                        .completeOnTimeout(timeoutResult(check), perCheckTimeout.toMillis(), TimeUnit.MILLISECONDS))
                .toList();

        List<CheckResult> results = futures.stream().map(CompletableFuture::join).toList();
        long totalMs = (System.nanoTime() - start) / 1_000_000;
        return new DiagnosisReport(ctx.domain(), ctx.targetIps(), ctx.targetIpSource(), totalMs, results);
    }

    private CheckResult runTimed(Check check, CheckContext ctx) {
        long start = System.nanoTime();
        CheckResult result;
        try {
            result = check.run(ctx);
        } catch (Exception e) {
            result = CheckResult.builder(check.id(), check.title())
                    .status(CheckStatus.ERROR)
                    .evidence("검사 실행 중 예외 발생: " + e)
                    .build();
        }
        return result.withElapsed((System.nanoTime() - start) / 1_000_000);
    }

    private CheckResult timeoutResult(Check check) {
        return CheckResult.builder(check.id(), check.title())
                .status(CheckStatus.ERROR)
                .evidence("검사가 제한 시간(" + perCheckTimeout.toSeconds() + "초)을 초과했습니다")
                .build()
                .withElapsed(perCheckTimeout.toMillis());
    }
}
