package dev.atharva.certreflex.demo;

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

import org.apache.catalina.connector.Connector;
import org.apache.coyote.http11.AbstractHttp11Protocol;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.pem.PemSslStoreBundle;
import org.springframework.boot.ssl.pem.PemSslStoreDetails;
import org.springframework.boot.tomcat.SslConnectorCustomizer;

import dev.atharva.certreflex.config.PkiProperties;

/**
 * The registered HTTPS listeners, keyed by service and by port.
 *
 * <p>Owns the two things only this class can do: reload a live connector's
 * certificate, and report which certificate a connector is currently
 * configured to present.
 */
public class DemoListeners {

    private static final Logger log = LoggerFactory.getLogger(DemoListeners.class);

    private final Map<String, Listener> byService;
    private final Map<Integer, Listener> byPort;

    DemoListeners(List<Listener> listeners) {
        this.byService = listeners.stream().collect(
                java.util.stream.Collectors.toMap(Listener::serviceName, Function.identity()));
        this.byPort = listeners.stream().collect(
                java.util.stream.Collectors.toMap(Listener::port, Function.identity()));
    }

    public List<Connector> connectors() {
        return byService.values().stream().map(Listener::connector).toList();
    }

    public Optional<Listener> forPort(int port) {
        return Optional.ofNullable(byPort.get(port));
    }

    public Optional<Listener> forService(String serviceName) {
        return Optional.ofNullable(byService.get(serviceName));
    }

    /**
     * Reloads the listener from the PEM files on disk.
     *
     * <p>The bundle is built here rather than fetched with
     * {@code sslBundles.getBundle(name)}: the registered bundle memoises its
     * KeyStore at startup, so reusing it would quietly reload the certificate
     * that was already in place. Locked decision 14.
     */
    public void reload(PkiProperties.Service service) {
        Listener listener = byService.get(service.name());
        if (listener == null) {
            throw new IllegalArgumentException("No listener registered for service " + service.name());
        }
        PemSslStoreDetails details = PemSslStoreDetails
                .forCertificate("file:" + service.certPath())
                .withPrivateKey("file:" + service.keyPath());
        listener.customizer().update(null, SslBundle.of(new PemSslStoreBundle(details, null)));
        log.info("RELOADED service_name={} port={} from {}",
                service.name(), listener.port(), service.certPath());
    }

    /**
     * The certificate the connector will present on the next handshake, read
     * from Tomcat's live SSLHostConfig.
     *
     * <p>Deliberately not read from the SslBundle: after a corruption
     * injection every call into {@code getStores().getKeyStore()} throws, and
     * this has to keep answering. Locked decision 15.
     */
    public Optional<X509Certificate> currentCertificate(Listener listener) {
        AbstractHttp11Protocol<?> protocol =
                (AbstractHttp11Protocol<?>) listener.connector().getProtocolHandler();
        for (SSLHostConfig hostConfig : protocol.findSslHostConfigs()) {
            for (SSLHostConfigCertificate certificate : hostConfig.getCertificates()) {
                try {
                    Optional<X509Certificate> found = first(certificate.getCertificateKeystore());
                    if (found.isPresent()) {
                        return found;
                    }
                } catch (Exception e) {
                    log.warn("Could not read the live certificate for service_name={}: {}",
                            listener.serviceName(), e.getMessage());
                }
            }
        }
        return Optional.empty();
    }

    private static Optional<X509Certificate> first(KeyStore keyStore) throws Exception {
        if (keyStore == null) {
            return Optional.empty();
        }
        for (Enumeration<String> aliases = keyStore.aliases(); aliases.hasMoreElements(); ) {
            if (keyStore.getCertificate(aliases.nextElement()) instanceof X509Certificate certificate) {
                return Optional.of(certificate);
            }
        }
        return Optional.empty();
    }

    public record Listener(String serviceName, int port, String bundleName,
            Connector connector, SslConnectorCustomizer customizer) {
    }
}
