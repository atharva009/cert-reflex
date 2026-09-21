package dev.atharva.certreflex.inventory;

import dev.atharva.certreflex.issuer.Serials;

import java.math.BigInteger;
import java.time.Instant;
import java.util.UUID;

/**
 * One row of the certs table. There is exactly one row per service_name for
 * the lifetime of the database; rotation updates it in place.
 *
 * <p>No private key material is ever stored here, only a path to it.
 */
public record CertRecord(
        UUID id,
        String serviceName,
        String commonName,
        BigInteger serialNumber,
        Instant notBefore,
        Instant notAfter,
        CertStatus status,
        String certPem,
        String certPath,
        String keyPath,
        Instant createdAt,
        Instant updatedAt) {

    public String serialHex() {
        return Serials.hex(serialNumber);
    }
}
