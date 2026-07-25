package io.github.potwings.mailcheck.engine;

import io.github.potwings.mailcheck.api.Check;
import io.github.potwings.mailcheck.api.CheckContext;
import io.github.potwings.mailcheck.api.CheckResult;
import io.github.potwings.mailcheck.api.CheckStatus;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;

class CheckEngineTest {

    private static final CheckContext CTX = new CheckContext("example.com", List.of("203.0.113.5"), "사용자 입력");

    private ExecutorService executor;

    @BeforeEach
    void setUp() {
        executor = Executors.newFixedThreadPool(4);
    }

    @AfterEach
    void tearDown() {
        executor.shutdownNow();
    }

    /** Test double: a check whose behaviour is supplied per-test. */
    private static Check check(String id, Function<CheckContext, CheckResult> body) {
        return new Check() {
            @Override
            public String id() {
                return id;
            }

            @Override
            public String title() {
                return id.toUpperCase();
            }

            @Override
            public CheckResult run(CheckContext context) {
                return body.apply(context);
            }
        };
    }

    private static Check passing(String id) {
        return check(id, ctx -> CheckResult.builder(id, id.toUpperCase())
                .status(CheckStatus.PASS)
                .evidence("ok")
                .build());
    }

    private static Check sleeping(String id, long millis) {
        return check(id, ctx -> {
            try {
                Thread.sleep(millis);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return CheckResult.builder(id, id.toUpperCase()).status(CheckStatus.PASS).build();
        });
    }

    private DiagnosisReport diagnose(List<Check> checks, Duration timeout) {
        return new CheckEngine(checks, timeout, executor).diagnose(CTX);
    }

    private static CheckResult resultOf(DiagnosisReport report, String checkId) {
        return report.results().stream()
                .filter(r -> r.checkId().equals(checkId))
                .findFirst()
                .orElseThrow(() -> new AssertionError(checkId + " 결과가 없습니다"));
    }

    @Test
    void 모든_검사_결과를_등록_순서대로_반환한다() {
        DiagnosisReport report = diagnose(
                List.of(passing("spf"), passing("dmarc"), passing("mx")), Duration.ofSeconds(5));

        assertThat(report.results()).extracting(CheckResult::checkId)
                .containsExactly("spf", "dmarc", "mx");
        assertThat(report.results()).allMatch(r -> r.status() == CheckStatus.PASS);
    }

    @Test
    void 컨텍스트의_도메인과_대상IP가_리포트에_담긴다() {
        DiagnosisReport report = diagnose(List.of(passing("spf")), Duration.ofSeconds(5));

        assertThat(report.domain()).isEqualTo("example.com");
        assertThat(report.targetIps()).containsExactly("203.0.113.5");
        assertThat(report.targetIpSource()).isEqualTo("사용자 입력");
        assertThat(report.totalElapsedMs()).isNotNegative();
    }

    @Test
    void 검사가_예외를_던지면_ERROR로_격리되고_나머지는_정상_수행된다() {
        Check exploding = check("rbl", ctx -> {
            throw new IllegalStateException("DNS 폭발");
        });

        DiagnosisReport report = diagnose(
                List.of(passing("spf"), exploding, passing("mx")), Duration.ofSeconds(5));

        CheckResult failed = resultOf(report, "rbl");
        assertThat(failed.status()).isEqualTo(CheckStatus.ERROR);
        assertThat(failed.evidence()).anyMatch(e -> e.contains("예외 발생") && e.contains("DNS 폭발"));
        assertThat(resultOf(report, "spf").status()).isEqualTo(CheckStatus.PASS);
        assertThat(resultOf(report, "mx").status()).isEqualTo(CheckStatus.PASS);
    }

    @Test
    void 제한시간을_초과한_검사만_ERROR가_되고_나머지_결과는_보존된다() {
        DiagnosisReport report = diagnose(
                List.of(passing("spf"), sleeping("ptr", 3_000)), Duration.ofMillis(150));

        CheckResult timedOut = resultOf(report, "ptr");
        assertThat(timedOut.status()).isEqualTo(CheckStatus.ERROR);
        assertThat(timedOut.evidence()).anyMatch(e -> e.contains("제한 시간"));
        assertThat(resultOf(report, "spf").status()).isEqualTo(CheckStatus.PASS);
    }

    @Test
    void 느린_검사가_있어도_전체_진단은_제한시간_수준에서_끝난다() {
        long start = System.nanoTime();
        diagnose(List.of(sleeping("ptr", 10_000), passing("spf")), Duration.ofMillis(200));
        long elapsedMs = (System.nanoTime() - start) / 1_000_000;

        assertThat(elapsedMs).isLessThan(5_000);
    }

    @Test
    void 검사들은_병렬로_실행된다() throws Exception {
        // 3개 검사가 동시에 시작되지 않으면 latch가 풀리지 않아 타임아웃 처리된다.
        CountDownLatch latch = new CountDownLatch(3);
        Function<CheckContext, CheckResult> body = ctx -> {
            latch.countDown();
            boolean allStarted;
            try {
                allStarted = latch.await(3, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                allStarted = false;
            }
            return CheckResult.builder("x", "X")
                    .status(allStarted ? CheckStatus.PASS : CheckStatus.FAIL)
                    .build();
        };

        DiagnosisReport report = diagnose(
                List.of(check("a", body), check("b", body), check("c", body)), Duration.ofSeconds(10));

        assertThat(report.results()).allMatch(r -> r.status() == CheckStatus.PASS);
    }

    @Test
    void 각_검사_결과에_소요시간이_기록된다() {
        DiagnosisReport report = diagnose(List.of(sleeping("spf", 50)), Duration.ofSeconds(5));

        assertThat(resultOf(report, "spf").elapsedMs()).isGreaterThanOrEqualTo(40);
    }

    @Test
    void 검사가_없으면_빈_결과를_반환한다() {
        DiagnosisReport report = diagnose(List.of(), Duration.ofSeconds(5));

        assertThat(report.results()).isEmpty();
    }
}
