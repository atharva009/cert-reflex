package dev.atharva.certreflex.bootstrap;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;

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
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.yaml.snakeyaml.Yaml;

import dev.atharva.certreflex.issuer.BouncyCastle;
import dev.atharva.certreflex.issuer.Pem;

/**
 * Stage A of the two-stage bootstrap, per locked decision 6.
 *
 * <p>Runs from {@code main()} before {@code SpringApplication.run()}, because
 * Tomcat cannot bind an SSL connector whose keystore file is missing and the
 * context does not exist yet. It touches no KMS, no Postgres and no Spring
 * bean, and reads the service list straight out of application.yml.
 *
 * <p>What it writes is a self-signed placeholder, not a real certificate.
 * Stage B replaces it with CA-signed material seconds later, which is the
 * system healing itself in front of the reviewer.
 */
public final class PlaceholderCertificates {

    private static final Logger log = LoggerFactory.getLogger(PlaceholderCertificates.class);

    private static final Duration VALIDITY = Duration.ofHours(1);
    private static final String CONFIG_RESOURCE = "/application.yml";

    private PlaceholderCertificates() {
    }

    /** Writes placeholders for every configured service that lacks usable material. */
    public static void writeMissing() {
        for (ServicePaths service : readServices()) {
            try {
                if (usable(service)) {
                    log.info("Stage A service_name={} placeholder not needed, certificate already present",
                            service.name());
                    continue;
                }
                BigInteger serial = write(service);
                log.info("Stage A service_name={} wrote self-signed placeholder serial={} to {}",
                        service.name(), serial.toString(16).toUpperCase(), service.certPath());
            } catch (Exception e) {
                // A connector that cannot bind is fatal, so do not swallow this.
                throw new IllegalStateException(
                        "Could not prepare placeholder material for " + service.name(), e);
            }
        }
    }

    private static boolean usable(ServicePaths service) {
        Path certPath = Path.of(service.certPath());
        Path keyPath = Path.of(service.keyPath());
        if (!Files.isReadable(certPath) || !Files.isReadable(keyPath)) {
            return false;
        }
        try (InputStream in = Files.newInputStream(certPath)) {
            CertificateFactory.getInstance("X.509").generateCertificate(in);
            return true;
        } catch (Exception e) {
            log.warn("Stage A service_name={} existing certificate is unparseable ({}), replacing it",
                    service.name(), e.getMessage());
            return false;
        }
    }

    private static BigInteger write(ServicePaths service) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", BouncyCastle.PROVIDER);
        generator.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
        KeyPair keyPair = generator.generateKeyPair();

        X509Certificate certificate = selfSign(keyPair, service.name());

        // Key first, then the cert, each staged through a temp file: locked
        // decision 13, so a watcher never sees a cert without its matching key.
        Pem.writeAtomically(Path.of(service.keyPath()), Pem.encode(keyPair.getPrivate()));
        Pem.writeAtomically(Path.of(service.certPath()), Pem.encode(certificate));
        return certificate.getSerialNumber();
    }

    private static X509Certificate selfSign(KeyPair keyPair, String serviceName) throws Exception {
        Instant notBefore = Instant.now().minus(Duration.ofSeconds(30));
        X500Name subject = new X500Name("CN=" + serviceName);

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject,
                new BigInteger(128, new SecureRandom()).abs().add(BigInteger.ONE),
                Date.from(notBefore),
                Date.from(notBefore.plus(VALIDITY)),
                subject,
                keyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        builder.addExtension(Extension.extendedKeyUsage, false,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
        builder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(
                List.of(new GeneralName(GeneralName.dNSName, "localhost"),
                        new GeneralName(GeneralName.dNSName, serviceName))
                        .toArray(new GeneralName[0])));

        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastle.PROVIDER)
                .getCertificate(builder.build(new JcaContentSignerBuilder("SHA256withECDSA")
                        .setProvider(BouncyCastle.PROVIDER)
                        .build(keyPair.getPrivate())));
    }

    /** Spring is not up yet, so the service list is read straight from the YAML. */
    @SuppressWarnings("unchecked")
    private static List<ServicePaths> readServices() {
        try (InputStream in = PlaceholderCertificates.class.getResourceAsStream(CONFIG_RESOURCE)) {
            if (in == null) {
                throw new IllegalStateException(CONFIG_RESOURCE + " is not on the classpath");
            }
            Map<String, Object> root = new Yaml().load(in);
            Map<String, Object> pki = (Map<String, Object>) root.get("pki");
            List<Map<String, String>> services = (List<Map<String, String>>) pki.get("services");
            return services.stream()
                    .map(service -> new ServicePaths(
                            service.get("name"), service.get("cert-path"), service.get("key-path")))
                    .toList();
        } catch (IOException e) {
            throw new IllegalStateException("Could not read " + CONFIG_RESOURCE, e);
        }
    }

    private record ServicePaths(String name, String certPath, String keyPath) {
    }
}
