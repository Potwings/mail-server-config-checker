package io.github.potwings.mailcheck.mail.meta;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.potwings.mailcheck.mail.intake.MailIntakeException;
import io.github.potwings.mailcheck.mail.json.MailJson;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Reads meta.json. IOExceptions propagate untouched (transient — the caller
 * retries on the next poll); malformed content becomes MailIntakeException
 * (permanent — the caller marks the directory processed).
 */
public class MailMetaParser {

    private final ObjectMapper mapper = MailJson.mapper();

    public MailMeta parse(Path metaFile) throws IOException {
        byte[] bytes = Files.readAllBytes(metaFile);
        try {
            return mapper.readValue(bytes, MailMeta.class);
        } catch (JacksonException e) {
            throw new MailIntakeException("meta.json 파싱 실패: " + metaFile, e);
        }
    }
}
