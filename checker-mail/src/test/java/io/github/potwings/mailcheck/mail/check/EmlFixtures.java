package io.github.potwings.mailcheck.mail.check;

import org.apache.james.jdkim.DKIMSigner;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/** Builds (optionally DKIM-signed) message.eml fixtures for the mail-based checks. */
public final class EmlFixtures {

    public static final String BASE_EML =
            "From: Sender <user@example.com>\r\n"
                    + "To: check-abc@mail-check.example\r\n"
                    + "Subject: test mail\r\n"
                    + "Date: Mon, 27 Jul 2026 10:00:00 +0900\r\n"
                    + "Message-ID: <20260727100000.abc@example.com>\r\n"
                    + "\r\n"
                    + "Hello DKIM\r\n";

    private EmlFixtures() {
    }

    public static KeyPair rsaKeyPair(int bits) {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(bits);
            return gen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Signs the mail and returns it with the DKIM-Signature header prepended. */
    public static String sign(String eml, KeyPair keyPair, String domain, String selector) {
        try {
            DKIMSigner signer = new DKIMSigner(
                    "v=1; a=rsa-sha256; c=relaxed/relaxed; d=" + domain + "; s=" + selector
                            + "; h=from:to:subject:date;",
                    keyPair.getPrivate());
            String header = signer.sign(
                    new ByteArrayInputStream(eml.getBytes(StandardCharsets.ISO_8859_1)));
            return header + "\r\n" + eml;
        } catch (Exception e) {
            throw new IllegalStateException("테스트 서명 생성 실패", e);
        }
    }

    /** DNS TXT value publishing the pair's public key. */
    public static String publicKeyTxt(KeyPair keyPair) {
        return "v=DKIM1; k=rsa; p="
                + Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
    }

    public static Path write(Path dir, String content) {
        try {
            Path file = dir.resolve("message.eml");
            Files.write(file, content.getBytes(StandardCharsets.ISO_8859_1));
            return file;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
