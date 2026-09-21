package dev.atharva.certreflex.spike;

import java.io.IOException;
import java.io.Writer;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemObject;

/**
 * Self-signed EC P-256 material for the hot-swap spike. This is the Stage A
 * mechanism from locked decision 6: placeholder certificates written before the
 * context starts, so Tomcat has something to bind its connectors to.
 *
 * <p>Writes are staged through a temp file in the same directory and moved into
 * place, because Spring's SSL bundle watcher can otherwise observe a
 * half-written PEM.
 */
public final class SpikeCertificates {

    private static final Duration VALIDITY = Duration.ofHours(1);

    private SpikeCertificates() {
    }

    /** Stage A: only write if the material is missing, never overwrite. */
    public static void writeIfAbsent(Path certPath, Path keyPath, String commonName) throws Exception {
        if (Files.exists(certPath) && Files.exists(keyPath)) {
            return;
        }
        write(certPath, keyPath, commonName);
    }

    /** Generates a fresh key pair and certificate and replaces what is on disk. */
    public static X509Certificate write(Path certPath, Path keyPath, String commonName) throws Exception {
        KeyPair keyPair = generateKeyPair();
        X509Certificate certificate = selfSign(keyPair, commonName);
        // Key first: a reader that catches the cert change alone would then find
        // a key that already matches it, rather than the previous key.
        writePem(keyPath, "PRIVATE KEY", keyPair.getPrivate().getEncoded());
        writePem(certPath, "CERTIFICATE", certificate.getEncoded());
        return certificate;
    }

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        generator.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
        return generator.generateKeyPair();
    }

    private static X509Certificate selfSign(KeyPair keyPair, String commonName) throws Exception {
        Instant notBefore = Instant.now();
        X500Name subject = new X500Name("CN=" + commonName);

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject,
                new BigInteger(128, new SecureRandom()).abs().add(BigInteger.ONE),
                Date.from(notBefore),
                Date.from(notBefore.plus(VALIDITY)),
                subject,
                keyPair.getPublic());

        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        builder.addExtension(Extension.extendedKeyUsage, false,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
        builder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(
                List.of(new GeneralName(GeneralName.dNSName, "localhost"),
                        new GeneralName(GeneralName.dNSName, commonName))
                        .toArray(new GeneralName[0])));

        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(builder.build(new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withECDSA")
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .build(keyPair.getPrivate())));
    }

    private static void writePem(Path target, String type, byte[] der) throws IOException {
        Files.createDirectories(target.getParent());
        Path staging = target.resolveSibling(target.getFileName() + ".tmp");
        try (Writer writer = Files.newBufferedWriter(staging);
             JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
            pemWriter.writeObject(new PemObject(type, der));
        }
        Files.move(staging, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }
}
