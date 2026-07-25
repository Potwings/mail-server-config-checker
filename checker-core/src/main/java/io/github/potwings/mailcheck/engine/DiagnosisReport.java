package io.github.potwings.mailcheck.engine;

import io.github.potwings.mailcheck.api.CheckResult;

import java.util.List;

public record DiagnosisReport(String domain, List<String> targetIps, String targetIpSource,
                              long totalElapsedMs, List<CheckResult> results) {
}
