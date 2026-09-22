package dev.atharva.certreflex.admin;

import java.time.Duration;
import java.time.Instant;

import dev.atharva.certreflex.config.PkiProperties;
import dev.atharva.certreflex.inventory.CertRecord;
import dev.atharva.certreflex.issuer.Serials;

/**
 * What the dashboard renders for one listener.
 *
 * <p>{@code secondsUntilExpiry} is computed here rather than in the browser:
 * the client's clock is not the server's, and a countdown that disagrees with
 * the inventory by a few seconds would undermine the one number the demo asks
 * a viewer to watch. It goes negative for a certificate that has expired and
 * is waiting to be remediated; that is real state and the UI should show it
 * rather than have it clamped away here.
 */
public record CertView(
        String serviceName,
        Integer port,
        String status,
        String serial,
        Instant notBefore,
        Instant notAfter,
        long secondsUntilExpiry) {

    static CertView of(CertRecord record, PkiProperties pkiProperties, Instant now) {
        return new CertView(
                record.serviceName(),
                portOf(record.serviceName(), pkiProperties),
                record.status().name(),
                Serials.hex(record.serialNumber()),
                record.notBefore(),
                record.notAfter(),
                Duration.between(now, record.notAfter()).toSeconds());
    }

    /** Null rather than a fake port for a row whose service is no longer configured. */
    private static Integer portOf(String serviceName, PkiProperties pkiProperties) {
        return pkiProperties.services().stream()
                .filter(service -> service.name().equals(serviceName))
                .map(PkiProperties.Service::port)
                .findFirst()
                .orElse(null);
    }
}
