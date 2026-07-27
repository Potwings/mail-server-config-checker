package io.github.potwings.mailcheck.mail.check.header;

import io.github.potwings.mailcheck.api.Check;
import io.github.potwings.mailcheck.api.CheckContext;
import io.github.potwings.mailcheck.api.CheckResult;
import io.github.potwings.mailcheck.api.CheckStatus;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Header quality per the mail-tester benchmark (PRD §4): missing To /
 * Message-ID / Date and header syntax slips are the main real-world point
 * losses, and a correctly configured MTA/submission chain adds these headers
 * automatically — absence signals a server misconfiguration, not content taste.
 * Content-quality headers (List-Unsubscribe 등) are out of scope by design.
 */
public class HeaderQualityCheck implements Check {

    // RFC 5322 field name: printable US-ASCII except colon.
    private static final Pattern FIELD_NAME = Pattern.compile("^[!-9;-~]+$");
    private static final Pattern MESSAGE_ID = Pattern.compile("^<[^<>@\\s]+@[^<>@\\s]+>$");
    // 헤더 블록 상한 — 본문까지 읽지 않기 위한 안전장치
    private static final int MAX_HEADER_LINES = 500;

    @Override
    public String id() {
        return "header-quality";
    }

    @Override
    public String title() {
        return "헤더 품질";
    }

    @Override
    public CheckResult run(CheckContext ctx) {
        CheckResult.Builder b = CheckResult.builder(id(), title());
        if (!ctx.hasEml()) {
            return b.status(CheckStatus.SKIP)
                    .evidence("메일 원문(message.eml)이 있어야 검사할 수 있음 — 실메일 수신 시 자동 수행")
                    .build();
        }

        List<String> logicalLines;
        try {
            logicalLines = readHeaderBlock(ctx);
        } catch (IOException e) {
            return b.status(CheckStatus.ERROR).evidence("message.eml 읽기 실패: " + e.getMessage()).build();
        }

        Map<String, List<String>> headers = new LinkedHashMap<>();
        List<String> malformed = new ArrayList<>();
        List<String> missingSpace = new ArrayList<>();
        for (String line : logicalLines) {
            int colon = line.indexOf(':');
            if (colon <= 0) {
                malformed.add(abbreviate(line));
                continue;
            }
            String name = line.substring(0, colon);
            if (!FIELD_NAME.matcher(name).matches()) {
                malformed.add(abbreviate(line));
                continue;
            }
            if (colon + 1 < line.length() && line.charAt(colon + 1) != ' ' && line.charAt(colon + 1) != '\t') {
                missingSpace.add(name);
            }
            headers.computeIfAbsent(name.toLowerCase(Locale.ROOT), k -> new ArrayList<>())
                    .add(line.substring(colon + 1).trim());
        }

        if (!malformed.isEmpty()) {
            b.atLeast(CheckStatus.WARN)
                    .evidence("형식이 잘못된 헤더 라인: " + String.join(" | ", malformed))
                    .guidance("발신 측 MTA/게이트웨이가 비표준 헤더를 만들고 있습니다 — 스팸 필터의 HDRS_MISSP류 감점 요인");
        }
        if (!missingSpace.isEmpty()) {
            b.atLeast(CheckStatus.WARN)
                    .evidence("콜론 뒤 공백이 없는 헤더: " + String.join(", ", missingSpace)
                            + " — 일부 스팸 필터가 형식 오류로 감점");
        }

        // 정상 설정된 MTA/submission이면 자동 부여되는 헤더 — 부재는 서버 설정 문제 신호
        requireHeader(headers, "message-id", "Message-ID", b);
        requireHeader(headers, "date", "Date", b);
        if (!headers.containsKey("to")) {
            b.atLeast(CheckStatus.WARN)
                    .evidence("To: 헤더 없음 — mail-tester류 도구와 다수 스팸 필터가 감점 (MISSING_HEADERS)")
                    .guidance("Bcc 단독 발송이 아니라면 To: 헤더가 포함되도록 발송 구성을 확인하세요");
        }

        for (String name : List.of("from", "to", "date", "message-id", "subject")) {
            List<String> values = headers.get(name);
            if (values != null && values.size() > 1) {
                b.atLeast(CheckStatus.WARN)
                        .evidence(displayName(name) + " 헤더가 " + values.size() + "개 — RFC 5322상 최대 1개, 다수 필터가 위조 신호로 취급");
            }
        }

        List<String> messageIds = headers.get("message-id");
        if (messageIds != null && !MESSAGE_ID.matcher(messageIds.get(0)).matches()) {
            b.atLeast(CheckStatus.WARN)
                    .evidence("Message-ID 형식이 표준(<고유값@도메인>)과 다름: " + abbreviate(messageIds.get(0)));
        }
        List<String> dates = headers.get("date");
        if (dates != null && !parsableDate(dates.get(0))) {
            b.atLeast(CheckStatus.WARN)
                    .evidence("Date 형식이 RFC 5322와 다름: " + abbreviate(dates.get(0)));
        }

        if (b.build().status() == CheckStatus.PASS) {
            b.evidence("필수 헤더(From, To, Date, Message-ID) 존재·형식 확인");
        }
        return b.build();
    }

    private static void requireHeader(Map<String, List<String>> headers, String key,
                                      String display, CheckResult.Builder b) {
        if (!headers.containsKey(key)) {
            b.atLeast(CheckStatus.FAIL)
                    .evidence(display + " 헤더 없음 — 정상 설정된 MTA/submission이라면 자동 부여되는 헤더")
                    .guidance("발송 경로(애플리케이션→submission→MTA)에서 " + display
                            + " 헤더가 붙는지 확인하세요. Postfix는 submission 경로가 아니면 보정하지 않을 수 있습니다");
        }
    }

    /** Unfolded logical header lines of the header block (up to the first blank line). */
    private List<String> readHeaderBlock(CheckContext ctx) throws IOException {
        List<String> logical = new ArrayList<>();
        try (BufferedReader r = Files.newBufferedReader(ctx.emlPath(), StandardCharsets.ISO_8859_1)) {
            StringBuilder current = null;
            String line;
            int read = 0;
            while ((line = r.readLine()) != null && read++ < MAX_HEADER_LINES) {
                if (line.isEmpty()) {
                    break;
                }
                if ((line.charAt(0) == ' ' || line.charAt(0) == '\t') && current != null) {
                    current.append(' ').append(line.trim());
                    continue;
                }
                if (current != null) {
                    logical.add(current.toString());
                }
                current = new StringBuilder(line);
            }
            if (current != null) {
                logical.add(current.toString());
            }
        }
        return logical;
    }

    private static boolean parsableDate(String value) {
        // RFC 5322 날짜 + 흔한 후행 주석("(KST)") 허용
        String v = value.replaceAll("\\(.*\\)\\s*$", "").trim();
        try {
            DateTimeFormatter.RFC_1123_DATE_TIME.parse(v);
            return true;
        } catch (DateTimeParseException e) {
            return false;
        }
    }

    private static String displayName(String lower) {
        return switch (lower) {
            case "from" -> "From";
            case "to" -> "To";
            case "date" -> "Date";
            case "message-id" -> "Message-ID";
            case "subject" -> "Subject";
            default -> lower;
        };
    }

    private static String abbreviate(String s) {
        String t = s.trim();
        return t.length() > 80 ? t.substring(0, 77) + "..." : t;
    }
}
