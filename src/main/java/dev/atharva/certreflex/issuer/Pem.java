package dev.atharva.certreflex.issuer;

import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

/** PEM encoding helpers. Private keys are emitted as PKCS#8. */
public final class Pem {

    private Pem() {
    }

    public static String encode(X509Certificate certificate) {
        try {
            return encode("CERTIFICATE", certificate.getEncoded());
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException("Could not encode certificate", e);
        }
    }

    public static String encode(List<X509Certificate> chain) {
        StringBuilder pem = new StringBuilder();
        chain.forEach(certificate -> pem.append(encode(certificate)));
        return pem.toString();
    }

    public static String encode(PrivateKey privateKey) {
        return encode("PRIVATE KEY", privateKey.getEncoded());
    }

    private static String encode(String type, byte[] der) {
        StringWriter out = new StringWriter();
        try (PemWriter writer = new PemWriter(out)) {
            writer.writeObject(new PemObject(type, der));
        } catch (IOException e) {
            throw new IllegalStateException("Could not write PEM", e);
        }
        return out.toString();
    }

    /** Staged through a temp file so a watcher never observes a partial write. */
    public static void writeAtomically(Path target, String contents) throws IOException {
        Files.createDirectories(target.toAbsolutePath().getParent());
        Path staging = target.resolveSibling(target.getFileName() + ".tmp");
        try (Writer writer = Files.newBufferedWriter(staging)) {
            writer.write(contents);
        }
        Files.move(staging, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }
}
