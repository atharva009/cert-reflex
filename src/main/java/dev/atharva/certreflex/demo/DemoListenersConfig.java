package dev.atharva.certreflex.demo;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.catalina.connector.Connector;
import org.apache.commons.logging.LogFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.ssl.PemSslBundleProperties;
import org.springframework.boot.autoconfigure.ssl.SslProperties;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.boot.tomcat.SslConnectorCustomizer;
import org.springframework.boot.tomcat.TomcatWebServerFactory;
import org.springframework.boot.tomcat.servlet.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.Ssl;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import dev.atharva.certreflex.config.PkiProperties;

/**
 * Registers one extra HTTPS connector per configured service, as spec section
 * 5.5 describes.
 *
 * <p>Each connector needs both halves of what Boot does for the connector it
 * builds itself: apply the bundle, and register an update handler. Boot only
 * wires the handler for its own connector, so a self-registered one that is
 * given the bundle alone will serve a stale certificate forever while the
 * inventory happily reports ACTIVE. Locked decision 11.
 *
 * <p>Registration runs as a loop with a log line per service, so a listener
 * missing its handler is visible at startup rather than inferred later from a
 * demo going wrong.
 */
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@Configuration(proxyBeanMethods = false)
public class DemoListenersConfig {

    private static final Logger log = LoggerFactory.getLogger(DemoListenersConfig.class);

    @Bean
    DemoListeners demoListeners(PkiProperties pkiProperties, SslBundles sslBundles, SslProperties sslProperties) {
        List<DemoListeners.Listener> listeners = new ArrayList<>();
        for (PkiProperties.Service service : pkiProperties.services()) {
            String bundleName = service.name();
            requireBundleMatchesService(sslProperties, service, bundleName);

            Connector connector = new Connector(TomcatWebServerFactory.DEFAULT_PROTOCOL);
            connector.setPort(service.port());

            SslConnectorCustomizer customizer = new SslConnectorCustomizer(
                    LogFactory.getLog(DemoListenersConfig.class), connector, Ssl.ClientAuth.NONE);
            customizer.customize(sslBundles.getBundle(bundleName), Map.of());

            // The second half. A null server name targets the connector's
            // default SSLHostConfig.
            sslBundles.addBundleUpdateHandler(bundleName, bundle -> {
                log.info("SSL bundle updated on disk service_name={} bundle={}, reloading port {}",
                        service.name(), bundleName, service.port());
                customizer.update(null, bundle);
            });

            listeners.add(new DemoListeners.Listener(
                    service.name(), service.port(), bundleName, connector, customizer));
            log.info("Listener registered service_name={} port={} bundle={} reload_handler=registered",
                    service.name(), service.port(), bundleName);
        }
        return new DemoListeners(listeners);
    }

    @Bean
    WebServerFactoryCustomizer<TomcatServletWebServerFactory> demoConnectors(DemoListeners listeners) {
        return factory -> factory.addAdditionalConnectors(listeners.connectors().toArray(new Connector[0]));
    }

    /**
     * The SSL bundle and the service entry are two declarations of the same two
     * filenames. If they drift, the listener serves a certificate the
     * remediator never rotates, which looks like nothing until a demo fails.
     */
    private static void requireBundleMatchesService(SslProperties sslProperties,
            PkiProperties.Service service, String bundleName) {
        PemSslBundleProperties bundle = sslProperties.getBundle().getPem().get(bundleName);
        if (bundle == null) {
            throw new IllegalStateException("No spring.ssl.bundle.pem." + bundleName
                    + " bundle for service '" + service.name() + "'");
        }
        requireSamePath(bundle.getKeystore().getCertificate(), service.certPath(),
                bundleName, service.name(), "certificate");
        requireSamePath(bundle.getKeystore().getPrivateKey(), service.keyPath(),
                bundleName, service.name(), "private key");
    }

    private static void requireSamePath(String bundlePath, String servicePath,
            String bundleName, String serviceName, String what) {
        Path fromBundle = normalise(bundlePath);
        Path fromService = normalise(servicePath);
        if (!fromBundle.equals(fromService)) {
            throw new IllegalStateException(("The %s path for listener '%s' disagrees with its service entry: "
                    + "spring.ssl.bundle.pem.%s resolves to %s, pki.services[%s] resolves to %s. "
                    + "They must name the same file, or the listener will serve a certificate "
                    + "the remediator never rotates.")
                            .formatted(what, serviceName, bundleName, fromBundle, serviceName, fromService));
        }
    }

    private static Path normalise(String location) {
        String path = location.startsWith("file:") ? location.substring("file:".length()) : location;
        return Path.of(path).toAbsolutePath().normalize();
    }
}
