package io.github.potwings.mailcheck.engine;

import io.github.potwings.mailcheck.api.CheckResult;

import java.util.List;

public record DiagnosisReport(String domain, String targetIp, String targetIpSource,
                              long totalElapsedMs, List<CheckResult> results) {
}
