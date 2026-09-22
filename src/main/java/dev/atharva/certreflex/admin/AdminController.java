package dev.atharva.certreflex.admin;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Locale;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import dev.atharva.certreflex.config.PkiProperties;
import dev.atharva.certreflex.events.CertEvent;
import dev.atharva.certreflex.events.CertEventRepository;
import dev.atharva.certreflex.inventory.CertRecord;
import dev.atharva.certreflex.inventory.CertRepository;
import dev.atharva.certreflex.inventory.CertStatus;
import dev.atharva.certreflex.remediator.CertRemediator;

/**
 * The surface the dashboard polls, plus the controls that break things on
 * purpose. Spec section 7.
 *
 * <p>Every read here comes from the inventory and the event table, never from
 * an SslBundle. Once a certificate file is garbage, reading the bundle throws
 * on every call, and a bundle-backed endpoint would fail at precisely the
 * moment the dashboard is meant to be showing the corruption. Locked
 * decision 15.
 *
 * <p>No authentication, deliberately: spec section 11 keeps this local-only and
 * unhosted, which is the reason an unauthenticated "corrupt this cert" button
 * is acceptable here and nowhere else.
 */
@RestController
@RequestMapping("/internal")
class AdminController {

    private static final int EVENT_LIMIT = 50;

    private final PkiProperties pkiProperties;
    private final CertRepository certRepository;
    private final CertEventRepository eventRepository;
    private final CertRemediator remediator;
    private final FailureInjector injector;

    AdminController(PkiProperties pkiProperties, CertRepository certRepository,
            CertEventRepository eventRepository, CertRemediator remediator, FailureInjector injector) {
        this.pkiProperties = pkiProperties;
        this.certRepository = certRepository;
        this.eventRepository = eventRepository;
        this.remediator = remediator;
        this.injector = injector;
    }

    @GetMapping("/certs")
    List<CertView> certs() {
        Instant now = Instant.now();
        return certRepository.findAll().stream()
                .map(record -> CertView.of(record, pkiProperties, now))
                .toList();
    }

    @GetMapping("/certs/{serviceName}")
    CertView cert(@PathVariable String serviceName) {
        return CertView.of(require(serviceName), pkiProperties, Instant.now());
    }

    /**
     * Works from any status, which is what makes it the recovery path for a
     * FAILED row (locked decision 27). {@code rotate} does not rethrow
     * (decision 26), so the row is read back afterwards: a caller sees FAILED
     * in the response if the rotation did not work.
     */
    @PostMapping("/certs/{serviceName}/rotate")
    CertView rotate(@PathVariable String serviceName) {
        CertRecord current = require(serviceName);
        CertStatus reason = current.status() == CertStatus.CORRUPTED
                ? CertStatus.CORRUPTED
                : CertStatus.EXPIRING;
        remediator.rotate(serviceName, reason);
        return CertView.of(require(serviceName), pkiProperties, Instant.now());
    }

    @GetMapping("/events")
    List<CertEvent> events() {
        return eventRepository.findRecent(EVENT_LIMIT);
    }

    @PostMapping("/failures/{serviceName}")
    InjectionResponse injectFailure(@PathVariable String serviceName, @RequestParam String type) {
        require(serviceName);
        PkiProperties.Service service = pkiProperties.service(serviceName);

        return switch (type.toUpperCase(Locale.ROOT)) {
            case "EXPIRE" -> {
                injector.injectExpiry(serviceName);
                yield new InjectionResponse(serviceName, "EXPIRE",
                        "not_after backdated; the watcher will detect it as EXPIRING");
            }
            case "CORRUPT" -> {
                try {
                    injector.injectCorruption(service);
                } catch (IOException e) {
                    throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,
                            "Could not overwrite " + service.certPath(), e);
                }
                yield new InjectionResponse(serviceName, "CORRUPT",
                        "certificate file overwritten; the watcher will detect it as CORRUPTED");
            }
            default -> throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "type must be EXPIRE or CORRUPT, was '" + type + "'");
        };
    }

    private CertRecord require(String serviceName) {
        return certRepository.findByServiceName(serviceName)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND,
                        "No inventory row for service '" + serviceName + "'"));
    }

    record InjectionResponse(String serviceName, String type, String detail) {
    }
}
