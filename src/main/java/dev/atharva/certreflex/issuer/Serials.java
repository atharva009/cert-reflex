package dev.atharva.certreflex.issuer;

import java.math.BigInteger;

/**
 * One rendering of a certificate serial, everywhere.
 *
 * <p>Serials are random positive 128-bit values, so the canonical form is 32
 * uppercase hex digits, zero-padded, which is exactly what
 * {@code openssl x509 -noout -serial} prints. {@code BigInteger.toString(16)}
 * drops leading zeros and produces a shorter string for roughly one serial in
 * sixteen, so a reviewer comparing the dashboard against openssl would see two
 * different prefixes for the same certificate.
 */
public final class Serials {

    private Serials() {
    }

    /** Pads to 32 digits; never truncates, so a wider value still renders in full. */
    public static String hex(BigInteger serialNumber) {
        return String.format("%032X", serialNumber);
    }
}
