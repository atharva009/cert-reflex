package dev.atharva.certreflex.admin;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import dev.atharva.certreflex.config.PkiProperties;
import dev.atharva.certreflex.events.CertEventRecorder;
import dev.atharva.certreflex.inventory.CertRepository;

/**
 * The two failure modes from spec 5.6, each hitting a different part of the
 * system so the watcher's two detection paths are both demonstrable.
 *
 * <p>Neither method touches the listener. The point is to break something and
 * let the system notice on its own.
 */
@Component
public class FailureInjector {

    private static final Logger log = LoggerFactory.getLogger(FailureInjector.class);

    private static final int GARBAGE_BYTES = 1024;

    private final CertRepository certRepository;
    private final CertEventRecorder events;

    public FailureInjector(CertRepository certRepository, CertEventRecorder events) {
        this.certRepository = certRepository;
        this.events = events;
    }

    /**
     * Backdates not_after. The file on disk is left alone, so this exercises
     * the expiry scan and nothing else.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void injectExpiry(String serviceName) {
        certRepository.expireNow(serviceName);
        events.injected(serviceName, "Injected failure: EXPIRE, not_after backdated");
        log.warn("INJECTED service_name={} type=EXPIRE", serviceName);
    }

    /**
     * Overwrites the certificate file with random bytes. The inventory row is
     * left alone, so only the corruption check can catch this.
     *
     * <p>Written in place rather than through the temp-and-move discipline the
     * rest of the code uses. That discipline exists so a reader never sees a
     * half-written valid file; here the file is deliberately invalid either
     * way, and an in-place overwrite is closer to what real corruption on disk
     * looks like.
     */
    public void injectCorruption(PkiProperties.Service service) throws IOException {
        byte[] garbage = new byte[GARBAGE_BYTES];
        new SecureRandom().nextBytes(garbage);
        Files.write(Path.of(service.certPath()), garbage);
        recordCorruptionInjected(service.name());
        log.warn("INJECTED service_name={} type=CORRUPT path={}", service.name(), service.certPath());
    }

    /** Recorded after the write, so a failed write leaves no misleading event. */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    void recordCorruptionInjected(String serviceName) {
        events.injected(serviceName, "Injected failure: CORRUPT, certificate file overwritten");
    }
}
