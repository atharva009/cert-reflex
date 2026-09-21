package dev.atharva.certreflex.issuer;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.time.Instant;

/**
 * Everything one issuance produces. Nothing here has been written to disk or to
 * the database; that is the remediator's job.
 *
 * @param chainPem leaf first, then the CA, which is what a listener's cert.pem holds
 * @param privateKeyPem PKCS#8, never persisted to the database
 */
public record IssuedCertificate(
        X509Certificate certificate,
        X509Certificate caCertificate,
        BigInteger serialNumber,
        Instant notBefore,
        Instant notAfter,
        String certificatePem,
        String chainPem,
        String privateKeyPem) {

    public String serialHex() {
        return Serials.hex(serialNumber);
    }
}
