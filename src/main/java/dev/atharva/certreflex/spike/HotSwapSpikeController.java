package dev.atharva.certreflex.spike;

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Enumeration;

import org.apache.coyote.http11.AbstractHttp11Protocol;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.boot.ssl.pem.PemSslStoreBundle;
import org.springframework.boot.ssl.pem.PemSslStoreDetails;
import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import dev.atharva.certreflex.spike.SpikeConnectorConfiguration.SpikeConnector;

/**
 * Reports what the connector is serving right now, and swaps the material on
 * disk on demand.
 *
 * <p>Both serials are read on every request, never cached at startup: the
 * connector serial comes from the live {@link SSLHostConfig} Tomcat is using,
 * the bundle serial from the registry Spring updates on reload. A cached value
 * would report a stale serial after a reload and fake a passing test.
 */
@Profile("spike")
@RestController
class HotSwapSpikeController {

    private static final Logger log = LoggerFactory.getLogger(HotSwapSpikeController.class);

    private final SslBundles sslBundles;
    private final SpikeConnector spikeConnector;

    HotSwapSpikeController(SslBundles sslBundles, SpikeConnector spikeConnector) {
        this.sslBundles = sslBundles;
        this.spikeConnector = spikeConnector;
    }

    /** Touches no SSL state, so it can tell a dropped connection from a broken handler. */
    @GetMapping(value = "/ping", produces = "text/plain")
    String ping() {
        return "ok\n";
    }

    @GetMapping(value = "/", produces = "text/plain")
    String serials() throws Exception {
        return "connector=" + connectorSerial() + "\nbundle=" + bundleSerial() + "\n";
    }

    /**
     * Writes new material and immediately reloads the connector, the way the
     * remediator would, instead of waiting for the file watcher.
     */
    @RequestMapping(value = "/swap-explicit", method = {RequestMethod.GET, RequestMethod.POST},
            produces = "text/plain")
    String swapExplicit() throws Exception {
        X509Certificate certificate = SpikeCertificates.write(
                HotSwapSpikeApplication.CERT_PATH,
                HotSwapSpikeApplication.KEY_PATH,
                HotSwapSpikeApplication.SERVICE_NAME);
        long start = System.nanoTime();
        // Not sslBundles.getBundle(): the registered bundle memoizes its
        // KeyStore, so it still holds the material read at startup until the
        // file watcher replaces the registration. Read the new files directly.
        spikeConnector.customizer().update(null, freshBundleFromDisk());
        long updateMicros = (System.nanoTime() - start) / 1000;
        String serial = hex(certificate.getSerialNumber());
        log.info("wrote new material for {} serial={} and reloaded the connector explicitly in {}us",
                HotSwapSpikeApplication.SERVICE_NAME, serial, updateMicros);
        return "written=" + serial + "\nupdate_micros=" + updateMicros + "\nat=" + Instant.now() + "\n";
    }

    @RequestMapping(value = "/swap", method = {RequestMethod.GET, RequestMethod.POST}, produces = "text/plain")
    String swap() throws Exception {
        X509Certificate certificate = SpikeCertificates.write(
                HotSwapSpikeApplication.CERT_PATH,
                HotSwapSpikeApplication.KEY_PATH,
                HotSwapSpikeApplication.SERVICE_NAME);
        String serial = hex(certificate.getSerialNumber());
        log.info("wrote new material for {} serial={} at {}",
                HotSwapSpikeApplication.SERVICE_NAME, serial, Instant.now());
        return "written=" + serial + "\nat=" + Instant.now() + "\n";
    }

    private static SslBundle freshBundleFromDisk() {
        PemSslStoreDetails details = PemSslStoreDetails
                .forCertificate("file:./" + HotSwapSpikeApplication.CERT_PATH)
                .withPrivateKey("file:./" + HotSwapSpikeApplication.KEY_PATH);
        return SslBundle.of(new PemSslStoreBundle(details, null));
    }

    /** The certificate Tomcat's current SSLHostConfig holds for this connector. */
    private String connectorSerial() throws Exception {
        AbstractHttp11Protocol<?> protocol =
                (AbstractHttp11Protocol<?>) spikeConnector.connector().getProtocolHandler();
        for (SSLHostConfig hostConfig : protocol.findSslHostConfigs()) {
            for (SSLHostConfigCertificate certificate : hostConfig.getCertificates()) {
                String serial = firstSerial(certificate.getCertificateKeystore());
                if (serial != null) {
                    return serial;
                }
            }
        }
        return "unknown";
    }

    /** What the SSL bundle registry currently holds under this bundle name. */
    private String bundleSerial() throws Exception {
        return firstSerial(sslBundles.getBundle(SpikeConnectorConfiguration.BUNDLE_NAME).getStores().getKeyStore());
    }

    private static String firstSerial(KeyStore keyStore) throws Exception {
        if (keyStore == null) {
            return null;
        }
        for (Enumeration<String> aliases = keyStore.aliases(); aliases.hasMoreElements(); ) {
            if (keyStore.getCertificate(aliases.nextElement()) instanceof X509Certificate certificate) {
                return hex(certificate.getSerialNumber());
            }
        }
        return null;
    }

    private static String hex(java.math.BigInteger serial) {
        return dev.atharva.certreflex.issuer.Serials.hex(serial);
    }
}
