package dev.atharva.certreflex.issuer;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import dev.atharva.certreflex.config.KmsProperties;
import dev.atharva.certreflex.config.PkiProperties;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.NotFoundException;

/**
 * The intermediate CA certificate that leaf certificates chain to.
 *
 * <p>KMS holds the private key and nothing else: it has no notion of a
 * certificate, so the CA certificate is a self-signed wrapper we mint over the
 * public key KMS reports, signed through that same KMS key.
 *
 * <p>Cached at {@code ./runtime/ca.pem} and re-minted whenever the cached
 * certificate's public key stops matching the key currently in KMS. LocalStack
 * does not persist keys across {@code docker compose down} and
 * {@code create-ca-key.sh} reissues in that case, so a stale ca.pem signed by a
 * key that no longer exists is a state this will actually hit.
 */
@Component
public class CertificateAuthority {

    private static final Logger log = LoggerFactory.getLogger(CertificateAuthority.class);

    private static final String SUBJECT_DN = "CN=cert-reflex intermediate CA";
    private static final Duration VALIDITY = Duration.ofDays(365);

    private final KmsClient kms;
    private final String caKeyId;
    private final Path caPath;
    private final X509Certificate certificate;

    public CertificateAuthority(KmsClient kms, KmsProperties kmsProperties, PkiProperties pkiProperties) {
        this.kms = kms;
        this.caKeyId = kmsProperties.requireCaKeyId();
        this.caPath = Path.of(pkiProperties.caPath());
        this.certificate = loadOrMint();
    }

    /** The CA certificate leaves chain to. */
    public X509Certificate certificate() {
        return certificate;
    }

    private X509Certificate loadOrMint() {
        PublicKey kmsPublicKey = fetchPublicKey();
        X509Certificate cached = readCached();
        if (cached != null && Arrays.equals(cached.getPublicKey().getEncoded(), kmsPublicKey.getEncoded())) {
            log.info("CA certificate loaded from {} serial={} keyId={}",
                    caPath, Serials.hex(cached.getSerialNumber()), caKeyId);
            return cached;
        }
        if (cached != null) {
            log.warn("Cached CA certificate at {} was signed by a different KMS key, re-minting", caPath);
        }
        return mint(kmsPublicKey);
    }

    /** Never throws: an unreadable or unparseable cache is simply replaced. */
    private X509Certificate readCached() {
        if (!Files.isReadable(caPath)) {
            return null;
        }
        try (InputStream in = Files.newInputStream(caPath)) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        } catch (Exception e) {
            log.warn("Could not read cached CA certificate at {} ({}), re-minting", caPath, e.getMessage());
            return null;
        }
    }

    private X509Certificate mint(PublicKey publicKey) {
        try {
            Instant notBefore = Instant.now();
            JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
            X500Name subject = new X500Name(SUBJECT_DN);

            JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    subject,
                    new BigInteger(128, new SecureRandom()).abs().add(BigInteger.ONE),
                    Date.from(notBefore),
                    Date.from(notBefore.plus(VALIDITY)),
                    subject,
                    publicKey);
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            builder.addExtension(Extension.keyUsage, true,
                    new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
            builder.addExtension(Extension.subjectKeyIdentifier, false,
                    extensionUtils.createSubjectKeyIdentifier(publicKey));

            X509Certificate minted = new JcaX509CertificateConverter()
                    .setProvider(BouncyCastle.PROVIDER)
                    .getCertificate(builder.build(new KmsContentSigner(kms, caKeyId)));

            Pem.writeAtomically(caPath, Pem.encode(minted));
            log.info("CA certificate minted serial={} keyId={} cached at {}",
                    Serials.hex(minted.getSerialNumber()), caKeyId, caPath);
            return minted;
        } catch (IOException | java.security.GeneralSecurityException e) {
            throw new IllegalStateException("Could not mint the CA certificate", e);
        }
    }

    private PublicKey fetchPublicKey() {
        byte[] spki;
        try {
            spki = kms.getPublicKey(GetPublicKeyRequest.builder().keyId(caKeyId).build())
                    .publicKey().asByteArray();
        } catch (NotFoundException e) {
            // The common case, and it has a one-command fix: LocalStack does not
            // persist KMS keys, so tearing the container down destroys the key
            // while .env goes on naming it. Only a missing key is translated
            // here; every other KMS failure keeps its own error.
            throw new IllegalStateException("""
                    The configured CA key id %s no longer exists in KMS.
                    LocalStack does not persist KMS keys across a container teardown, so
                    `docker compose down` destroys the key while .env still points at it.
                    Run ./scripts/create-ca-key.sh to fix this: it detects the stale id
                    and issues a replacement.""".formatted(caKeyId), e);
        }
        try {
            // KMS returns a DER SubjectPublicKeyInfo, which is what X509EncodedKeySpec takes.
            return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(spki));
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException("Could not read the CA public key from KMS", e);
        }
    }
}
