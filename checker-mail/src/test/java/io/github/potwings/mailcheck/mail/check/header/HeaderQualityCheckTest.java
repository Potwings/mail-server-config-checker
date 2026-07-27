package io.github.potwings.mailcheck.mail.check.header;

import io.github.potwings.mailcheck.api.CheckContext;
import io.github.potwings.mailcheck.api.CheckResult;
import io.github.potwings.mailcheck.api.CheckStatus;
import io.github.potwings.mailcheck.mail.check.EmlFixtures;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class HeaderQualityCheckTest {

    @TempDir
    Path tempDir;

    private final HeaderQualityCheck check = new HeaderQualityCheck();

    private CheckResult run(String eml) {
        Path path = EmlFixtures.write(tempDir, eml);
        return check.run(new CheckContext("example.com", List.of("203.0.113.5"), "SMTP 세션 접속 IP",
                true, new CheckContext.MailSession("user@example.com", "mail.example.com"), path));
    }

    @Test
    void eml이_없으면_SKIP() {
        CheckResult r = check.run(new CheckContext("example.com", List.of(), null));

        assertThat(r.status()).isEqualTo(CheckStatus.SKIP);
    }

    @Test
    void 필수_헤더가_모두_정상이면_PASS() {
        CheckResult r = run(EmlFixtures.BASE_EML);

        assertThat(r.status()).isEqualTo(CheckStatus.PASS);
        assertThat(r.evidence()).anyMatch(e -> e.contains("필수 헤더"));
    }

    @Test
    void Message_ID가_없으면_FAIL() {
        CheckResult r = run(EmlFixtures.BASE_EML.replace(
                "Message-ID: <20260727100000.abc@example.com>\r\n", ""));

        assertThat(r.status()).isEqualTo(CheckStatus.FAIL);
        assertThat(r.evidence()).anyMatch(e -> e.contains("Message-ID 헤더 없음"));
    }

    @Test
    void Date가_없으면_FAIL() {
        CheckResult r = run(EmlFixtures.BASE_EML.replace(
                "Date: Mon, 27 Jul 2026 10:00:00 +0900\r\n", ""));

        assertThat(r.status()).isEqualTo(CheckStatus.FAIL);
        assertThat(r.evidence()).anyMatch(e -> e.contains("Date 헤더 없음"));
    }

    @Test
    void To가_없으면_WARN() {
        CheckResult r = run(EmlFixtures.BASE_EML.replace(
                "To: check-abc@mail-check.example\r\n", ""));

        assertThat(r.status()).isEqualTo(CheckStatus.WARN);
        assertThat(r.evidence()).anyMatch(e -> e.contains("To: 헤더 없음"));
    }

    @Test
    void 콜론_뒤_공백이_없으면_WARN() {
        CheckResult r = run(EmlFixtures.BASE_EML.replace(
                "Subject: test mail", "Subject:test mail"));

        assertThat(r.status()).isEqualTo(CheckStatus.WARN);
        assertThat(r.evidence()).anyMatch(e -> e.contains("콜론 뒤 공백"));
    }

    @Test
    void 콜론이_없는_헤더_라인은_WARN() {
        CheckResult r = run(EmlFixtures.BASE_EML.replace(
                "Subject: test mail", "BrokenHeaderLine"));

        assertThat(r.status()).isEqualTo(CheckStatus.WARN);
        assertThat(r.evidence()).anyMatch(e -> e.contains("형식이 잘못된 헤더 라인"));
    }

    @Test
    void Message_ID_형식이_다르면_WARN() {
        CheckResult r = run(EmlFixtures.BASE_EML.replace(
                "Message-ID: <20260727100000.abc@example.com>", "Message-ID: not-an-id"));

        assertThat(r.status()).isEqualTo(CheckStatus.WARN);
        assertThat(r.evidence()).anyMatch(e -> e.contains("Message-ID 형식"));
    }

    @Test
    void Date_형식이_다르면_WARN() {
        CheckResult r = run(EmlFixtures.BASE_EML.replace(
                "Date: Mon, 27 Jul 2026 10:00:00 +0900", "Date: 2026-07-27 10:00"));

        assertThat(r.status()).isEqualTo(CheckStatus.WARN);
        assertThat(r.evidence()).anyMatch(e -> e.contains("Date 형식"));
    }

    @Test
    void 후행_주석이_있는_Date는_정상() {
        CheckResult r = run(EmlFixtures.BASE_EML.replace(
                "Date: Mon, 27 Jul 2026 10:00:00 +0900",
                "Date: Mon, 27 Jul 2026 10:00:00 +0900 (KST)"));

        assertThat(r.status()).isEqualTo(CheckStatus.PASS);
    }

    @Test
    void 중복_From은_WARN() {
        CheckResult r = run("From: another@example.com\r\n" + EmlFixtures.BASE_EML);

        assertThat(r.status()).isEqualTo(CheckStatus.WARN);
        assertThat(r.evidence()).anyMatch(e -> e.contains("From 헤더가 2개"));
    }

    @Test
    void 접힌_헤더는_한_헤더로_취급된다() {
        CheckResult r = run(EmlFixtures.BASE_EML.replace(
                "To: check-abc@mail-check.example\r\n",
                "To: check-abc@mail-check.example,\r\n\tsecond@example.com\r\n"));

        assertThat(r.status()).isEqualTo(CheckStatus.PASS);
    }
}
