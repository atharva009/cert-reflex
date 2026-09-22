package dev.atharva.certreflex.remediator;

import java.time.Duration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import dev.atharva.certreflex.inventory.CertRecord;
import dev.atharva.certreflex.inventory.CertRepository;
import dev.atharva.certreflex.inventory.CertStatus;

/**
 * Temporary: rotates demo-a once so this code is verifiable before the watcher
 * exists. Deleted when the watcher lands; the admin API's manual rotate is a
 * separate thing and comes later.
 */
@Profile("rotate-check")
@Order(Ordered.LOWEST_PRECEDENCE)
@Component
class RotateCheckRunner implements ApplicationRunner {

    private static final String SERVICE = "demo-a";

    private final CertRemediator remediator;
    private final CertRepository repository;
    private final Duration delay;

    RotateCheckRunner(CertRemediator remediator, CertRepository repository,
            @Value("${rotate-check.delay:PT0S}") Duration delay) {
        this.remediator = remediator;
        this.repository = repository;
        this.delay = delay;
    }

    @Override
    public void run(ApplicationArguments args) throws Exception {
        if (!delay.isZero()) {
            System.out.println("ROTATE-CHECK waiting " + delay.toSeconds() + "s before rotating " + SERVICE);
            Thread.sleep(delay.toMillis());
        }
        CertRecord before = repository.findByServiceName(SERVICE).orElseThrow();
        System.out.println("ROTATE-CHECK before status=" + before.status() + " serial=" + before.serialHex());

        long start = System.nanoTime();
        remediator.rotate(SERVICE, CertStatus.EXPIRING);
        long millis = (System.nanoTime() - start) / 1_000_000;

        CertRecord after = repository.findByServiceName(SERVICE).orElseThrow();
        System.out.println("ROTATE-CHECK after  status=" + after.status() + " serial=" + after.serialHex());
        System.out.println("ROTATE-CHECK rotation took " + millis + "ms");
    }
}
