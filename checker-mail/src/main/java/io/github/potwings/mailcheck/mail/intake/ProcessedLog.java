package io.github.potwings.mailcheck.mail.intake;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.HashSet;
import java.util.Set;

/**
 * Append-only log of processed incoming directory names — prevents re-diagnosis
 * after a restart. A crash between processing and logging costs at most one
 * duplicate card on the next poll (accepted trade-off, see m7-plan).
 */
public class ProcessedLog {

    private final Path file;
    private final Set<String> processed = new HashSet<>();

    public ProcessedLog(Path file) throws IOException {
        this.file = file;
        if (file.getParent() != null) {
            Files.createDirectories(file.getParent());
        }
        if (Files.exists(file)) {
            for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                if (!line.isBlank()) {
                    processed.add(line.trim());
                }
            }
        }
    }

    public synchronized boolean contains(String dirName) {
        return processed.contains(dirName);
    }

    public synchronized void markProcessed(String dirName) throws IOException {
        if (!processed.add(dirName)) {
            return;
        }
        Files.writeString(file, dirName + System.lineSeparator(), StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);
    }
}
