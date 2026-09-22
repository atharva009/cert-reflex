package dev.atharva.certreflex.watcher;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import dev.atharva.certreflex.inventory.CertRecord;
import dev.atharva.certreflex.inventory.CertStatus;
import dev.atharva.certreflex.issuer.Pem;

/**
 * Plain JUnit, no Spring. The corruption check is the only logic in the project
 * subtle enough that a silent mistake in it would look like a healthy system.
 */
class OnDiskCertificateCheckTest {

    private static final BouncyCastleProvider BC = new BouncyCastleProvider();

    @TempDir
    Path tempDir;

    private OnDiskCertificateCheck check;
    private Path certPath;

    @BeforeEach
    void setUp() {
        check = new OnDiskCertificateCheck();
        certPath = tempDir.resolve("cert.pem");
    }

    @Test
    void healthyWhenTheFileMatchesTheRow() throws Exception {
        X509Certificate leaf = selfSigned("demo-a");
        X509Certificate ca = selfSigned("cert-reflex intermediate CA");
        String chain = Pem.encode(java.util.List.of(leaf, ca));
        Files.writeString(certPath, chain);

        assertThat(check.check(recordWith(chain))).isEqualTo(OnDiskCertificateCheck.Result.OK);
    }

    @Test
    void readsTheLeafRatherThanTheWholeChain() throws Exception {
        // The CA is second in both files. A check that parsed every certificate
        // and compared the last one would pass this test only by accident, so
        // assert the leaf's key is what decides: same leaf, different CA.
        X509Certificate leaf = selfSigned("demo-a");
        String rowChain = Pem.encode(java.util.List.of(leaf, selfSigned("CA one")));
        String diskChain = Pem.encode(java.util.List.of(leaf, selfSigned("CA two")));
        Files.writeString(certPath, diskChain);

        assertThat(check.check(recordWith(rowChain))).isEqualTo(OnDiskCertificateCheck.Result.OK);
    }

    @Test
    void missingWhenThereIsNoFile() throws Exception {
        String chain = Pem.encode(java.util.List.of(selfSigned("demo-a"), selfSigned("ca")));

        assertThat(check.check(recordWith(chain))).isEqualTo(OnDiskCertificateCheck.Result.MISSING);
    }

    @Test
    void unparseableWhenTheFileIsGarbage() throws Exception {
        String chain = Pem.encode(java.util.List.of(selfSigned("demo-a"), selfSigned("ca")));
        Files.write(certPath, randomBytes());

        assertThat(check.check(recordWith(chain))).isEqualTo(OnDiskCertificateCheck.Result.UNPARSEABLE);
    }

    @Test
    void keyMismatchWhenTheFileIsAValidCertificateForADifferentKey() throws Exception {
        // Exactly what a Stage A placeholder looks like: parseable, right
        // subject, wrong key.
        String rowChain = Pem.encode(java.util.List.of(selfSigned("demo-a"), selfSigned("ca")));
        Files.writeString(certPath, Pem.encode(selfSigned("demo-a")));

        assertThat(check.check(recordWith(rowChain))).isEqualTo(OnDiskCertificateCheck.Result.KEY_MISMATCH);
    }

    @Test
    void corruptedIsTrueForEveryResultExceptOk() {
        assertThat(OnDiskCertificateCheck.Result.OK.corrupted()).isFalse();
        assertThat(OnDiskCertificateCheck.Result.MISSING.corrupted()).isTrue();
        assertThat(OnDiskCertificateCheck.Result.UNPARSEABLE.corrupted()).isTrue();
        assertThat(OnDiskCertificateCheck.Result.KEY_MISMATCH.corrupted()).isTrue();
    }

    private CertRecord recordWith(String certPem) {
        Instant now = Instant.now();
        return new CertRecord(UUID.randomUUID(), "demo-a", "demo-a", BigInteger.ONE,
                now, now.plusSeconds(120), CertStatus.ACTIVE, certPem,
                certPath.toString(), tempDir.resolve("key.pem").toString(), now, now);
    }

    private static byte[] randomBytes() {
        byte[] bytes = new byte[1024];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    private static X509Certificate selfSigned(String commonName) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", BC);
        generator.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
        KeyPair keyPair = generator.generateKeyPair();

        Instant notBefore = Instant.now();
        X500Name subject = new X500Name("CN=" + commonName);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject,
                new BigInteger(128, new SecureRandom()).abs().add(BigInteger.ONE),
                Date.from(notBefore),
                Date.from(notBefore.plus(Duration.ofHours(1))),
                subject,
                keyPair.getPublic());
        return new JcaX509CertificateConverter().setProvider(BC).getCertificate(
                builder.build(new JcaContentSignerBuilder("SHA256withECDSA")
                        .setProvider(BC).build(keyPair.getPrivate())));
    }
}
