package dev.atharva.certreflex.events;

import java.time.Instant;

/**
 * One row of cert_events. This exists to make the backend's behaviour visible
 * in the dashboard, not as a durable audit trail.
 */
public record CertEvent(
        long id,
        String serviceName,
        CertEventType eventType,
        String message,
        Instant createdAt) {
}
