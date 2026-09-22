package dev.atharva.certreflex.demo;

import java.io.IOException;
import java.nio.file.Path;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Component;

import dev.atharva.certreflex.config.PkiProperties;
import dev.atharva.certreflex.issuer.Pem;

/**
 * Writes a service's certificate material to disk and reloads its listener.
 *
 * <p>The one place that owns "these bytes are now this listener's
 * certificate": bootstrap uses it for a service's first certificate and the
 * remediator will use it for every rotation, so the write order and the reload
 * cannot drift apart between the two.
 *
 * <p>The explicit reload is what makes the swap deterministic, around 60ms
 * rather than waiting on the file watcher. The watcher stays enabled as a
 * backstop for changes made behind this class's back, and a duplicate reload
 * is harmless.
 */
@Component
public class CertificateInstaller {

    private static final Logger log = LoggerFactory.getLogger(CertificateInstaller.class);

    private final ObjectProvider<DemoListeners> listeners;

    public CertificateInstaller(ObjectProvider<DemoListeners> listeners) {
        this.listeners = listeners;
    }

    public void install(PkiProperties.Service service, String chainPem, String privateKeyPem) throws IOException {
        // Key first, then the cert, each staged through a temp file, so no
        // reader ever sees a certificate without its matching key.
        Pem.writeAtomically(Path.of(service.keyPath()), privateKeyPem);
        Pem.writeAtomically(Path.of(service.certPath()), chainPem);

        DemoListeners registered = listeners.getIfAvailable();
        if (registered == null || registered.forService(service.name()).isEmpty()) {
            log.debug("No listener registered for service_name={}, wrote files only", service.name());
            return;
        }
        registered.reload(service);
    }
}
