package dev.atharva.certreflex.inventory;

/** The cert state machine from spec section 10. */
public enum CertStatus {
    ACTIVE,
    EXPIRING,
    CORRUPTED,
    ROTATING,
    FAILED
}
