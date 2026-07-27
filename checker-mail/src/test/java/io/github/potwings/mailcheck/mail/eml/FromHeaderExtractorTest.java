package io.github.potwings.mailcheck.mail.eml;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class FromHeaderExtractorTest {

    @TempDir
    Path dir;

    private final FromHeaderExtractor extractor = new FromHeaderExtractor();

    private Optional<String> extract(String eml) throws IOException {
        Path f = dir.resolve("message.eml");
        Files.writeString(f, eml);
        return extractor.extractFromDomain(f);
    }

    @Test
    void 단순_From_주소에서_도메인을_추출() throws IOException {
        assertThat(extract("""
                From: sender@example.com
                To: check-1@mail-check.example
                Subject: test

                body
                """)).contains("example.com");
    }

    @Test
    void display_name과_꺾쇠_주소를_처리() throws IOException {
        assertThat(extract("""
                From: "Kim, Chulsoo (QA)" <qa.team@Example.COM>
                Subject: test

                body
                """)).contains("example.com");
    }

    @Test
    void 접힌_헤더를_처리() throws IOException {
        assertThat(extract("""
                From: Long Display Name
                 <sender@example.com>
                Subject: test

                body
                """)).contains("example.com");
    }

    @Test
    void 그룹_주소는_첫_mailbox_사용() throws IOException {
        assertThat(extract("""
                From: Ops Team: alpha@example.com, beta@example.net;
                Subject: test

                body
                """)).contains("example.com");
    }

    @Test
    void From이_없으면_empty() throws IOException {
        assertThat(extract("""
                To: check-1@mail-check.example
                Subject: no from

                body
                """)).isEmpty();
    }

    @Test
    void 도메인이_유효하지_않으면_empty() throws IOException {
        assertThat(extract("""
                From: broken@no-dot
                Subject: test

                body
                """)).isEmpty();
    }

    @Test
    void 파일이_없으면_empty() {
        assertThat(extractor.extractFromDomain(dir.resolve("missing.eml"))).isEmpty();
    }
}
