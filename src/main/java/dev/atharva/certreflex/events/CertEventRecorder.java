package dev.atharva.certreflex.events;

import org.springframework.stereotype.Service;

/**
 * Thin front door for writing events, so call sites stay one line.
 *
 * <p>Deliberately not transactional: every method joins the caller's
 * transaction, which is what makes an event row atomic with the status change
 * it describes.
 */
@Service
public class CertEventRecorder {

    private final CertEventRepository repository;

    public CertEventRecorder(CertEventRepository repository) {
        this.repository = repository;
    }

    public void detectedExpiring(String serviceName, String message) {
        repository.insert(serviceName, CertEventType.DETECTED_EXPIRING, message);
    }

    public void detectedCorrupted(String serviceName, String message) {
        repository.insert(serviceName, CertEventType.DETECTED_CORRUPTED, message);
    }

    public void issuing(String serviceName, String message) {
        repository.insert(serviceName, CertEventType.ISSUING, message);
    }

    public void swapped(String serviceName, String message) {
        repository.insert(serviceName, CertEventType.SWAPPED, message);
    }

    public void failed(String serviceName, String message) {
        repository.insert(serviceName, CertEventType.FAILED, message);
    }
}
