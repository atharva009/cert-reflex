package dev.atharva.certreflex.watcher;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import dev.atharva.certreflex.config.PkiProperties;
import dev.atharva.certreflex.inventory.CertLifecycle;
import dev.atharva.certreflex.inventory.CertRecord;
import dev.atharva.certreflex.inventory.CertRepository;
import dev.atharva.certreflex.inventory.CertStatus;
import dev.atharva.certreflex.remediator.CertRemediator;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;

/**
 * Finds certificates that are nearly expired or no longer match what is on
 * disk, and hands them to the remediator.
 *
 * <p>A plain scheduled method, not a Spring Batch tasklet: this overrides spec
 * section 5.3 per locked decision 2. There are no batch semantics here and the
 * metadata tables are not worth their cost at a five-second cadence.
 *
 * <p>Each pass has two phases, in this order: remediate anything a previous
 * pass marked, then detect and mark. Splitting them across passes is what
 * gives EXPIRING and CORRUPTED a full watcher interval of dwell time. Doing
 * both in one pass is correct but invisible: the row spends about a
 * millisecond in EXPIRING, so a dashboard polling once a second never renders
 * it, and the amber state becomes dead code. This mirrors spec 5.3's own
 * step 2 / step 3 split.
 *
 * <p>The scan is sequential on purpose. Three services at roughly 100ms each is
 * nothing, and concurrency would scramble the event ordering the dashboard's
 * log depends on.
 */
@Component
public class CertWatcherJob {

    private static final Logger log = LoggerFactory.getLogger(CertWatcherJob.class);

    private static final Duration LOCK_AT_MOST_FOR = Duration.ofSeconds(30);
    private static final Duration SLOW_PASS_THRESHOLD = LOCK_AT_MOST_FOR.dividedBy(2);

    private final PkiProperties pkiProperties;
    private final CertRepository certRepository;
    private final OnDiskCertificateCheck onDiskCheck;
    private final CertLifecycle lifecycle;
    private final CertRemediator remediator;

    public CertWatcherJob(PkiProperties pkiProperties, CertRepository certRepository,
            OnDiskCertificateCheck onDiskCheck, CertLifecycle lifecycle, CertRemediator remediator) {
        this.pkiProperties = pkiProperties;
        this.certRepository = certRepository;
        this.onDiskCheck = onDiskCheck;
        this.lifecycle = lifecycle;
        this.remediator = remediator;
    }

    /**
     * Public and non-final because ShedLock's default PROXY_METHOD interception
     * cannot wrap the method otherwise, and would silently run unlocked.
     */
    @Scheduled(fixedDelayString = "${pki.watcher-interval}")
    @SchedulerLock(name = "cert-watcher", lockAtLeastFor = "PT2S", lockAtMostFor = "PT30S")
    public void scan() {
        long startedAt = System.nanoTime();

        int remediated = remediateMarked();
        int detected = detect();

        reportDuration(startedAt, remediated, detected);
    }

    /**
     * Phase one: rotate what an earlier pass marked. Runs before detection so a
     * row marked in this same pass waits a full interval before rotating.
     */
    private int remediateMarked() {
        List<CertRecord> marked = certRepository.findAwaitingRemediation();
        for (CertRecord record : marked) {
            // The status the earlier pass set is the detection reason.
            remediator.rotate(record.serviceName(), record.status());
        }
        return marked.size();
    }

    /** Phase two: find newly expiring or corrupted services and mark them. */
    private int detect() {
        Map<String, Detection> detections = new LinkedHashMap<>();
        for (CertRecord record : certRepository.findDueForRotation(pkiProperties.rotateThreshold())) {
            detections.put(record.serviceName(), new Detection(CertStatus.EXPIRING,
                    "Less than " + pkiProperties.rotateThreshold().toSeconds()
                            + "s of validity remain, expires at " + record.notAfter()));
        }
        for (CertRecord record : certRepository.findAll()) {
            if (record.status() != CertStatus.ACTIVE) {
                continue;
            }
            OnDiskCertificateCheck.Result result = checkQuietly(record);
            if (result != null && result.corrupted()) {
                // Corruption wins over expiry: it is the more specific finding,
                // and the listener is already serving something unexpected.
                detections.put(record.serviceName(), new Detection(CertStatus.CORRUPTED,
                        "On-disk certificate " + describe(result)));
            }
        }

        detections.forEach(this::mark);
        return detections.size();
    }

    private void mark(String serviceName, Detection detection) {
        if (detection.reason() == CertStatus.CORRUPTED) {
            lifecycle.markCorrupted(serviceName, detection.message());
        } else {
            lifecycle.markExpiring(serviceName, detection.message());
        }
        // No rotation here: the next pass picks this row up, which is what
        // makes the marked state observable.
    }

    /** One unreadable file must not abandon the scan for the other services. */
    private OnDiskCertificateCheck.Result checkQuietly(CertRecord record) {
        try {
            return onDiskCheck.check(record);
        } catch (Exception e) {
            log.warn("Corruption check failed for service_name={}, skipping it this pass: {}",
                    record.serviceName(), e.toString());
            return null;
        }
    }

    private void reportDuration(long startedAt, int remediated, int detected) {
        Duration elapsed = Duration.ofNanos(System.nanoTime() - startedAt);
        if (elapsed.compareTo(SLOW_PASS_THRESHOLD) > 0) {
            log.warn("Watcher pass took {}ms, over half of lockAtMostFor ({}s); "
                    + "a pass that outlives the lock would let a second instance run concurrently",
                    elapsed.toMillis(), LOCK_AT_MOST_FOR.toSeconds());
        } else {
            log.debug("Watcher pass finished in {}ms, {} remediated, {} newly detected",
                    elapsed.toMillis(), remediated, detected);
        }
    }

    private static String describe(OnDiskCertificateCheck.Result result) {
        return switch (result) {
            case MISSING -> "is missing";
            case UNPARSEABLE -> "does not parse";
            case KEY_MISMATCH -> "has a different public key than the inventory";
            case OK -> "is healthy";
        };
    }

    private record Detection(CertStatus reason, String message) {
    }
}
