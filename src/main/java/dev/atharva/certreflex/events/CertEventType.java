package dev.atharva.certreflex.events;

/**
 * Event kinds the dashboard's log feed renders.
 *
 * <p>{@link #INJECTED} is not in spec section 6's list. It is here because an
 * injection is an operator action, not something the system observed: folding
 * it into DETECTED_EXPIRING or DETECTED_CORRUPTED would put a detection in the
 * log seconds before the watcher actually detected anything, and the log's
 * whole job is to show when the system noticed. event_type is TEXT, so this
 * needs no migration.
 */
public enum CertEventType {
    /** An operator asked for a failure; the message names which. */
    INJECTED,
    DETECTED_EXPIRING,
    DETECTED_CORRUPTED,
    ISSUING,
    SWAPPED,
    FAILED
}
