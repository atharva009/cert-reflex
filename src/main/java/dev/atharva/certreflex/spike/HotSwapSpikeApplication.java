package dev.atharva.certreflex.spike;

import java.nio.file.Path;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.flyway.autoconfigure.FlywayAutoConfiguration;
import org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration;

/**
 * Spike: does a certificate written to disk under a running, self-registered
 * Tomcat connector actually reach new TLS handshakes, without dropping
 * connections that are already open?
 *
 * <p>Run with the {@code spike} profile, which defines the {@code demo-a} SSL
 * bundle. No database: the datasource and Flyway are excluded deliberately.
 */
@SpringBootApplication(exclude = {DataSourceAutoConfiguration.class, FlywayAutoConfiguration.class})
public class HotSwapSpikeApplication {

    static final String SERVICE_NAME = "demo-a";
    static final Path CERT_PATH = Path.of("runtime", SERVICE_NAME, "cert.pem");
    static final Path KEY_PATH = Path.of("runtime", SERVICE_NAME, "key.pem");

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        // Stage A: Tomcat cannot bind an SSL connector against missing files, so
        // placeholder material has to exist before the context starts.
        SpikeCertificates.writeIfAbsent(CERT_PATH, KEY_PATH, SERVICE_NAME);
        SpringApplication.run(HotSwapSpikeApplication.class, args);
    }
}
