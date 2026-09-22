package dev.atharva.certreflex.remediator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import dev.atharva.certreflex.config.PkiProperties;
import dev.atharva.certreflex.demo.CertificateInstaller;
import dev.atharva.certreflex.inventory.CertLifecycle;
import dev.atharva.certreflex.inventory.CertStatus;
import dev.atharva.certreflex.issuer.CertificateIssuer;
import dev.atharva.certreflex.issuer.IssuedCertificate;

/**
 * Renews one service's certificate and swaps it in without dropping
 * connections, per spec section 5.4.
 *
 * <p>Deliberately not transactional, and it must stay that way. Each state
 * change commits on its own through {@link CertLifecycle} so a dashboard
 * polling once a second can watch the row move ROTATING then ACTIVE. Wrapping
 * this method in a transaction would collapse the whole rotation into one
 * commit and make the intermediate state invisible. Locked decision 5.
 */
@Service
public class CertRemediator {

    private static final Logger log = LoggerFactory.getLogger(CertRemediator.class);

    private final PkiProperties pkiProperties;
    private final CertificateIssuer issuer;
    private final CertificateInstaller installer;
    private final CertLifecycle lifecycle;

    public CertRemediator(PkiProperties pkiProperties, CertificateIssuer issuer,
            CertificateInstaller installer, CertLifecycle lifecycle) {
        this.pkiProperties = pkiProperties;
        this.issuer = issuer;
        this.installer = installer;
        this.lifecycle = lifecycle;
    }

    /**
     * Rotates one service. Never throws: a failure is recorded on the row and
     * logged, so a watcher pass covering several services is not abandoned
     * partway because one of them failed.
     *
     * @param reason what the watcher detected, EXPIRING or CORRUPTED
     */
    public void rotate(String serviceName, CertStatus reason) {
        if (reason != CertStatus.EXPIRING && reason != CertStatus.CORRUPTED) {
            throw new IllegalArgumentException(
                    "Rotation reason must be EXPIRING or CORRUPTED, was " + reason);
        }
        PkiProperties.Service service = pkiProperties.service(serviceName);

        lifecycle.markRotating(serviceName, "Rotating after " + reason);
        try {
            IssuedCertificate issued = issuer.issue(serviceName);
            installer.install(service, issued.chainPem(), issued.privateKeyPem());
            // Updates the existing row; rotation never inserts. Locked decision 4.
            lifecycle.completeRotation(serviceName, issued.serialNumber(),
                    issued.notBefore(), issued.notAfter(), issued.chainPem());
        } catch (Exception e) {
            recordFailure(serviceName, e);
        }
    }

    /**
     * Failures are recorded and not retried, per spec section 11. The row is
     * left FAILED, which takes it out of {@code findDueForRotation}, so nothing
     * will pick it up again on its own.
     */
    private void recordFailure(String serviceName, Exception cause) {
        log.error("Rotation failed for service_name={}: {}", serviceName, cause.toString(), cause);
        try {
            lifecycle.markFailed(serviceName, "Rotation failed: " + cause);
        } catch (Exception recordingFailure) {
            // Never let the bookkeeping failure hide the real one.
            recordingFailure.addSuppressed(cause);
            log.error("Could not record the failure for service_name={} either; "
                    + "the row is left in ROTATING", serviceName, recordingFailure);
        }
    }
}
