package dev.atharva.certreflex.events;

/** Event kinds the dashboard's log feed renders. */
public enum CertEventType {
    DETECTED_EXPIRING,
    DETECTED_CORRUPTED,
    ISSUING,
    SWAPPED,
    FAILED
}
