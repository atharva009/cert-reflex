package dev.atharva.certreflex.issuer;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import dev.atharva.certreflex.config.KmsProperties;
import dev.atharva.certreflex.config.PkiProperties;
import software.amazon.awssdk.services.kms.KmsClient;

/**
 * Issues a short-lived leaf certificate for one managed service.
 *
 * <p>Pure: it returns material and writes nothing. The leaf key pair is
 * generated locally because the process needs it to terminate TLS; the CA key
 * stays in KMS and only ever sees a digest.
 */
@Component
public class CertificateIssuer {

    private static final Logger log = LoggerFactory.getLogger(CertificateIssuer.class);

    /** Covers clock skew between host and container; a 2-minute cert cannot absorb much. */
    private static final java.time.Duration BACKDATE = java.time.Duration.ofSeconds(30);

    private final KmsClient kms;
    private final String caKeyId;
    private final PkiProperties pkiProperties;
    private final CertificateAuthority certificateAuthority;
    private final CertificateBuilder certificateBuilder;

    public CertificateIssuer(KmsClient kms, KmsProperties kmsProperties, PkiProperties pkiProperties,
            CertificateAuthority certificateAuthority, CertificateBuilder certificateBuilder) {
        this.kms = kms;
        this.caKeyId = kmsProperties.requireCaKeyId();
        this.pkiProperties = pkiProperties;
        this.certificateAuthority = certificateAuthority;
        this.certificateBuilder = certificateBuilder;
    }

    public IssuedCertificate issue(String serviceName) {
        PkiProperties.Service service = pkiProperties.service(serviceName);

        Instant now = Instant.now();
        Instant notBefore = now.minus(BACKDATE);
        Instant notAfter = now.plus(pkiProperties.certValidity());

        KeyPair leafKeyPair = generateLeafKeyPair();
        X509Certificate caCertificate = certificateAuthority.certificate();
        X509Certificate leaf = certificateBuilder.build(
                service.name(),
                service.commonName(),
                leafKeyPair.getPublic(),
                notBefore,
                notAfter,
                caCertificate,
                // One signer per certificate: KmsContentSigner is single use.
                new KmsContentSigner(kms, caKeyId));

        IssuedCertificate issued = new IssuedCertificate(
                leaf,
                caCertificate,
                leaf.getSerialNumber(),
                notBefore,
                notAfter,
                Pem.encode(leaf),
                Pem.encode(List.of(leaf, caCertificate)),
                Pem.encode(leafKeyPair.getPrivate()));

        log.info("ISSUED service_name={} serial={} not_before={} not_after={}",
                service.name(), issued.serialHex(), notBefore, notAfter);
        return issued;
    }

    private static KeyPair generateLeafKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", BouncyCastle.PROVIDER);
            generator.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
            return generator.generateKeyPair();
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException("Could not generate a leaf key pair", e);
        }
    }
}
