package dev.atharva.certreflex.watcher;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.springframework.stereotype.Component;

import dev.atharva.certreflex.inventory.CertRecord;

/**
 * Answers one question about one service: does the certificate on disk still
 * match the inventory row?
 *
 * <p>The comparison is by public key, per spec 5.3 and locked decision 20.
 * Serial or timestamp comparisons look equivalent and are not: the public key
 * is the only field tying the file to the private key the listener holds.
 *
 * <p>Both sides are two-certificate chains, leaf first then the CA.
 * {@link CertificateFactory#generateCertificate} reads exactly one certificate
 * from the stream, which is the leaf. Reading the whole chain and taking the
 * last entry would compare the CA's key and report every healthy service as
 * corrupted.
 */
@Component
public class OnDiskCertificateCheck {

    public enum Result {
        /** The file matches the inventory row. */
        OK,
        /** No readable file where the inventory says there should be one. */
        MISSING,
        /** Present but not a certificate, which is what the CORRUPT injection produces. */
        UNPARSEABLE,
        /** Parses, but it is not the certificate this row describes. */
        KEY_MISMATCH;

        public boolean corrupted() {
            return this != OK;
        }
    }

    public Result check(CertRecord record) {
        Path certPath = Path.of(record.certPath());
        if (!Files.isReadable(certPath)) {
            return Result.MISSING;
        }
        X509Certificate onDisk;
        X509Certificate expected;
        try (InputStream in = Files.newInputStream(certPath)) {
            onDisk = leafOf(in);
            // cert_pem holds the same chain that was written to disk, so the
            // leaf has to be extracted from it the same way.
            expected = leafOf(new ByteArrayInputStream(
                    record.certPem().getBytes(StandardCharsets.US_ASCII)));
        } catch (Exception e) {
            return Result.UNPARSEABLE;
        }
        return Arrays.equals(onDisk.getPublicKey().getEncoded(), expected.getPublicKey().getEncoded())
                ? Result.OK
                : Result.KEY_MISMATCH;
    }

    private static X509Certificate leafOf(InputStream in) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
    }
}
