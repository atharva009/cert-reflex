package dev.atharva.certreflex.inventory;

import java.math.BigInteger;
import java.time.Instant;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import dev.atharva.certreflex.events.CertEventRecorder;

/**
 * Every state transition, one commit each.
 *
 * <p>Locked decision 5: each method here is its own transaction, so the
 * dashboard polling once a second can observe EXPIRING and ROTATING as distinct
 * states. If a whole rotation committed at once those states would never be
 * visible and the amber and blue panel colours would be dead code.
 *
 * <p>Two rules this class exists to enforce, and which reviews should check:
 * no method performs more than one transition, and nothing that wraps a full
 * rotation may be annotated {@code @Transactional}. The event row is written
 * inside the same transaction as the status change it describes, which is why
 * {@link CertEventRecorder} has no transaction annotations of its own.
 */
@Service
public class CertLifecycle {

    private static final Logger log = LoggerFactory.getLogger(CertLifecycle.class);

    private final CertRepository certRepository;
    private final CertEventRecorder events;

    public CertLifecycle(CertRepository certRepository, CertEventRecorder events) {
        this.certRepository = certRepository;
        this.events = events;
    }

    /** First row for a service: ACTIVE plus the SWAPPED event, in one commit. */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void activateNew(String serviceName, String commonName, BigInteger serialNumber,
            Instant notBefore, Instant notAfter, String certPem, String certPath, String keyPath) {
        certRepository.insert(serviceName, commonName, serialNumber, notBefore, notAfter,
                CertStatus.ACTIVE, certPem, certPath, keyPath);
        events.swapped(serviceName, "Issued and installed certificate " + hex(serialNumber));
        log.info("ACTIVE service_name={} serial={}", serviceName, hex(serialNumber));
    }

    /** Event only: there is no row to transition yet, or none that changes state. */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordIssuing(String serviceName, String message) {
        events.issuing(serviceName, message);
        log.info("ISSUING service_name={} {}", serviceName, message);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void markExpiring(String serviceName, String message) {
        certRepository.updateStatus(serviceName, CertStatus.EXPIRING);
        events.detectedExpiring(serviceName, message);
        log.info("EXPIRING service_name={} {}", serviceName, message);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void markCorrupted(String serviceName, String message) {
        certRepository.updateStatus(serviceName, CertStatus.CORRUPTED);
        events.detectedCorrupted(serviceName, message);
        log.info("CORRUPTED service_name={} {}", serviceName, message);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void markRotating(String serviceName, String message) {
        certRepository.updateStatus(serviceName, CertStatus.ROTATING);
        events.issuing(serviceName, message);
        log.info("ROTATING service_name={} {}", serviceName, message);
    }

    /** Back to ACTIVE on the existing row. Never inserts; see locked decision 4. */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void completeRotation(String serviceName, BigInteger serialNumber,
            Instant notBefore, Instant notAfter, String certPem) {
        certRepository.updateAfterRotation(serviceName, serialNumber, notBefore, notAfter, certPem);
        events.swapped(serviceName, "Swapped in certificate " + hex(serialNumber));
        log.info("ACTIVE service_name={} serial={}", serviceName, hex(serialNumber));
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void markFailed(String serviceName, String message) {
        certRepository.updateStatus(serviceName, CertStatus.FAILED);
        events.failed(serviceName, message);
        log.warn("FAILED service_name={} {}", serviceName, message);
    }

    private static String hex(BigInteger serialNumber) {
        return serialNumber.toString(16).toUpperCase();
    }
}
