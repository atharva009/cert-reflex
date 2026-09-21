package dev.atharva.certreflex.issuer;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.springframework.stereotype.Component;

/** Builds the leaf certificate for one service and signs it with the supplied signer. */
@Component
public class CertificateBuilder {

    private static final SecureRandom RANDOM = new SecureRandom();

    public X509Certificate build(String serviceName, String commonName, PublicKey leafPublicKey,
            Instant notBefore, Instant notAfter, X509Certificate caCertificate, ContentSigner signer) {
        try {
            JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();

            // Taking the CA certificate rather than an issuer DN string makes the
            // leaf's issuer byte-identical to the CA's subject, which is what
            // chain building actually compares.
            JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    caCertificate,
                    randomSerial(),
                    Date.from(notBefore),
                    Date.from(notAfter),
                    new javax.security.auth.x500.X500Principal("CN=" + commonName),
                    leafPublicKey);

            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            // digitalSignature only: keyEncipherment means RSA key transport and
            // is meaningless on an EC certificate, whatever the spec doc says.
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
            builder.addExtension(Extension.extendedKeyUsage, false,
                    new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
            // Reviewers connect to https://localhost:8443, so "localhost" has to be
            // present or hostname verification fails for any client not passing -k.
            builder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(
                    List.of(new GeneralName(GeneralName.dNSName, "localhost"),
                            new GeneralName(GeneralName.dNSName, serviceName))
                            .toArray(new GeneralName[0])));
            builder.addExtension(Extension.subjectKeyIdentifier, false,
                    extensionUtils.createSubjectKeyIdentifier(leafPublicKey));
            builder.addExtension(Extension.authorityKeyIdentifier, false,
                    extensionUtils.createAuthorityKeyIdentifier(caCertificate));

            return new JcaX509CertificateConverter()
                    .setProvider(BouncyCastle.PROVIDER)
                    .getCertificate(builder.build(signer));
        } catch (java.security.GeneralSecurityException | java.io.IOException e) {
            throw new IllegalStateException("Could not build a leaf certificate for " + serviceName, e);
        }
    }

    private static BigInteger randomSerial() {
        return new BigInteger(128, RANDOM).abs().add(BigInteger.ONE);
    }
}
