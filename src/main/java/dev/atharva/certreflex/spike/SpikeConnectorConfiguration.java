package dev.atharva.certreflex.spike;

import java.util.Map;

import org.apache.catalina.connector.Connector;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.boot.tomcat.SslConnectorCustomizer;
import org.springframework.boot.tomcat.TomcatWebServerFactory;
import org.springframework.boot.tomcat.servlet.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.Ssl;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

/**
 * Registers one extra HTTPS connector on 8443 backed by the {@code demo-a} SSL
 * bundle, the way spec section 5.5 describes for the demo listeners.
 *
 * <p>Boot wires SSL reloads for the connector it builds from {@code server.*}
 * properties in {@code TomcatWebServerFactory.customizeSsl}, which does two
 * distinct things: apply the bundle via {@link SslConnectorCustomizer}, and
 * separately register an {@code SslBundles} update handler. A connector we
 * register ourselves only gets the first half, so the handler below is not
 * optional: without it the bundle reloads and the connector goes on serving
 * the old certificate.
 */
@Profile("spike")
@Configuration(proxyBeanMethods = false)
class SpikeConnectorConfiguration {

    private static final Log logger = LogFactory.getLog(SpikeConnectorConfiguration.class);

    static final String BUNDLE_NAME = "demo-a";
    static final int PORT = 8443;

    private final SslBundles sslBundles;

    SpikeConnectorConfiguration(SslBundles sslBundles) {
        this.sslBundles = sslBundles;
    }

    @Bean
    SpikeConnector spikeConnector() {
        Connector connector = new Connector(TomcatWebServerFactory.DEFAULT_PROTOCOL);
        connector.setPort(PORT);

        SslConnectorCustomizer customizer = new SslConnectorCustomizer(logger, connector, Ssl.ClientAuth.NONE);
        customizer.customize(sslBundles.getBundle(BUNDLE_NAME), Map.of());

        // Passing a null server name makes the customizer target the
        // connector's default SSLHostConfig.
        sslBundles.addBundleUpdateHandler(BUNDLE_NAME, bundle -> {
            logger.info("SSL bundle '" + BUNDLE_NAME + "' updated, reloading connector on port " + PORT);
            customizer.update(null, bundle);
        });
        logger.info("Registered connector on port " + PORT + " for bundle '" + BUNDLE_NAME + "'");
        return new SpikeConnector(connector, customizer);
    }

    @Bean
    WebServerFactoryCustomizer<TomcatServletWebServerFactory> spikeConnectorCustomizer(SpikeConnector spikeConnector) {
        return factory -> factory.addAdditionalConnectors(spikeConnector.connector());
    }

    /**
     * Holder so the controller can read live state off the running connector
     * and drive a reload without waiting for the file watcher.
     */
    record SpikeConnector(Connector connector, SslConnectorCustomizer customizer) {
    }
}
