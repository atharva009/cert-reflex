package dev.atharva.certreflex.bootstrap;

import java.nio.file.Path;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import dev.atharva.certreflex.config.PkiProperties;
import dev.atharva.certreflex.inventory.CertLifecycle;
import dev.atharva.certreflex.inventory.CertRepository;
import dev.atharva.certreflex.issuer.CertificateIssuer;
import dev.atharva.certreflex.issuer.IssuedCertificate;
import dev.atharva.certreflex.issuer.Pem;

/**
 * Stage B of the two-stage bootstrap, per locked decision 6.
 *
 * <p>For any configured service with no inventory row, issues a real CA-signed
 * certificate through the normal issuance path and replaces the Stage A
 * placeholder on disk. A fresh clone therefore boots on placeholders and heals
 * into real certificates within seconds.
 *
 * <p>Idempotent, and not a rotation path: a service that already has a row is
 * left entirely alone.
 */
@Component
public class InventoryBootstrap implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(InventoryBootstrap.class);

    private final PkiProperties pkiProperties;
    private final CertRepository certRepository;
    private final CertificateIssuer issuer;
    private final CertLifecycle lifecycle;

    public InventoryBootstrap(PkiProperties pkiProperties, CertRepository certRepository,
            CertificateIssuer issuer, CertLifecycle lifecycle) {
        this.pkiProperties = pkiProperties;
        this.certRepository = certRepository;
        this.issuer = issuer;
        this.lifecycle = lifecycle;
    }

    @Override
    public void run(ApplicationArguments args) throws Exception {
        for (PkiProperties.Service service : pkiProperties.services()) {
            if (certRepository.findByServiceName(service.name()).isPresent()) {
                log.info("Stage B service_name={} already in the inventory, nothing to do", service.name());
                continue;
            }
            issueFirstCertificate(service);
        }
    }

    private void issueFirstCertificate(PkiProperties.Service service) throws Exception {
        lifecycle.recordIssuing(service.name(), "No inventory row, issuing first certificate");

        IssuedCertificate issued = issuer.issue(service.name());

        // Key first, then the cert: locked decision 13.
        Pem.writeAtomically(Path.of(service.keyPath()), issued.privateKeyPem());
        Pem.writeAtomically(Path.of(service.certPath()), issued.chainPem());

        // No connector reload here: the application owns no HTTPS connectors
        // yet. When the demo listeners land, the explicit reload from locked
        // decision 14 goes here, constructing the bundle from these files
        // rather than fetching the registered one.

        lifecycle.activateNew(
                service.name(),
                service.commonName(),
                issued.serialNumber(),
                issued.notBefore(),
                issued.notAfter(),
                issued.chainPem(),
                service.certPath(),
                service.keyPath());

        log.info("Stage B service_name={} serial={} installed at {}",
                service.name(), issued.serialHex(), service.certPath());
    }
}
