package dev.atharva.certreflex.bootstrap;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import dev.atharva.certreflex.inventory.CertLifecycle;
import dev.atharva.certreflex.inventory.CertRecord;
import dev.atharva.certreflex.inventory.CertRepository;
import dev.atharva.certreflex.inventory.CertStatus;

/**
 * Rescues rows left in ROTATING by a process that died mid-rotation.
 *
 * <p>The window is narrow but real: a crash between writing the new material
 * to disk and committing the new serial leaves the row describing the old
 * certificate while the new one is already on disk. Nothing else picks that up
 * — Stage B skips rows that exist, the expiry scan filters on ACTIVE, the
 * remediation scan filters on EXPIRING and CORRUPTED, and the corruption check
 * only examines ACTIVE rows — so the listener would serve an expired
 * certificate indefinitely while the inventory reported ROTATING.
 *
 * <p>The fix is to hand the orphan back to the loop that already works rather
 * than build a second recovery path. CORRUPTED is the honest label: the row and
 * the disk genuinely disagree, which is exactly what the corruption check
 * exists to describe, and the next watcher pass rotates it.
 *
 * <p><strong>Single instance only.</strong> This is safe because exactly one
 * instance of this application ever runs. With two, a row legitimately in
 * ROTATING on another node would be stomped by this node's startup and rotated
 * twice. ShedLock's presence implies multi-instance thinking, so if that ever
 * becomes real this reset needs an ownership or heartbeat check first.
 */
@Order(Ordered.HIGHEST_PRECEDENCE)
@Component
public class StaleRotationReset implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(StaleRotationReset.class);

    private final CertRepository certRepository;
    private final CertLifecycle lifecycle;

    public StaleRotationReset(CertRepository certRepository, CertLifecycle lifecycle) {
        this.certRepository = certRepository;
        this.lifecycle = lifecycle;
    }

    @Override
    public void run(ApplicationArguments args) {
        // findAll rather than a new query: this runs once, over a handful of
        // rows, and the repository surface stays as narrow as it was.
        List<CertRecord> orphaned = certRepository.findAll().stream()
                .filter(record -> record.status() == CertStatus.ROTATING)
                .toList();

        for (CertRecord record : orphaned) {
            log.warn("Resetting service_name={} from ROTATING to CORRUPTED: a previous rotation did not "
                    + "complete, so the row still describes serial {} while the file on disk may not. "
                    + "The watcher will re-issue on its next pass.",
                    record.serviceName(), record.serialHex());
            lifecycle.markCorrupted(record.serviceName(),
                    "Previous rotation did not complete before shutdown; re-issuing");
        }
    }
}
