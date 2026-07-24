package io.github.potwings.mailcheck.api;

import java.util.ArrayList;
import java.util.List;

/**
 * Outcome of a single check: status + evidence (why) + guidance (how to fix).
 */
public record CheckResult(String checkId, String title, CheckStatus status,
                          List<String> evidence, List<String> guidance, long elapsedMs) {

    public CheckResult withElapsed(long ms) {
        return new CheckResult(checkId, title, status, evidence, guidance, ms);
    }

    public static Builder builder(String checkId, String title) {
        return new Builder(checkId, title);
    }

    public static final class Builder {
        private final String checkId;
        private final String title;
        private CheckStatus status = CheckStatus.PASS;
        private final List<String> evidence = new ArrayList<>();
        private final List<String> guidance = new ArrayList<>();

        private Builder(String checkId, String title) {
            this.checkId = checkId;
            this.title = title;
        }

        /** Overwrites the status unconditionally. */
        public Builder status(CheckStatus s) {
            this.status = s;
            return this;
        }

        /** Raises the status only if the new one is more severe. */
        public Builder atLeast(CheckStatus s) {
            if (s.isWorseThan(this.status)) {
                this.status = s;
            }
            return this;
        }

        public Builder evidence(String line) {
            this.evidence.add(line);
            return this;
        }

        public Builder guidance(String line) {
            this.guidance.add(line);
            return this;
        }

        public CheckResult build() {
            return new CheckResult(checkId, title, status, List.copyOf(evidence), List.copyOf(guidance), 0);
        }
    }
}
