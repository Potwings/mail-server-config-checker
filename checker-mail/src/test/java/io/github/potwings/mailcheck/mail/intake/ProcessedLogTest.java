package io.github.potwings.mailcheck.mail.intake;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

class ProcessedLogTest {

    @TempDir
    Path dir;

    @Test
    void 기록한_디렉터리는_재기동_후에도_유지된다() throws IOException {
        Path file = dir.resolve("processed.log");
        ProcessedLog log = new ProcessedLog(file);
        log.markProcessed("20260727T100000Z-Q1");
        log.markProcessed("20260727T100001Z-Q2");

        ProcessedLog reloaded = new ProcessedLog(file);

        assertThat(reloaded.contains("20260727T100000Z-Q1")).isTrue();
        assertThat(reloaded.contains("20260727T100001Z-Q2")).isTrue();
        assertThat(reloaded.contains("20260727T100002Z-Q3")).isFalse();
    }

    @Test
    void 중복_기록은_한_줄만_남긴다() throws IOException {
        Path file = dir.resolve("processed.log");
        ProcessedLog log = new ProcessedLog(file);
        log.markProcessed("dup");
        log.markProcessed("dup");

        assertThat(java.nio.file.Files.readAllLines(file)).containsExactly("dup");
    }

    @Test
    void 로그_파일이_없어도_기동한다() throws IOException {
        ProcessedLog log = new ProcessedLog(dir.resolve("sub").resolve("processed.log"));

        assertThat(log.contains("anything")).isFalse();
    }
}
