package dev.atharva.certreflex.config;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Certificate lifecycle timings and the list of services this system manages.
 *
 * <p>The service list is the single definition of the managed fleet: bootstrap,
 * the demo listeners, the watcher and the remediator all read it from here.
 *
 * <p>Every path this application writes to must resolve inside
 * {@code runtimeRoot}, and that is checked here, during binding, rather than in
 * a startup callback. File writes have no transaction to roll back: a test or a
 * typo that redirects a cert path somewhere unexpected produces a green build
 * and a broken demo. Binding happens before any bean that injects these
 * properties is constructed, so nothing can write a file ahead of the check.
 */
@ConfigurationProperties(prefix = "pki")
public record PkiProperties(
        Duration certValidity,
        Duration rotateThreshold,
        Duration watcherInterval,
        String runtimeRoot,
        String caPath,
        List<Service> services) {

    public static final String DEFAULT_RUNTIME_ROOT = "./runtime";

    public PkiProperties {
        runtimeRoot = (runtimeRoot == null || runtimeRoot.isBlank()) ? DEFAULT_RUNTIME_ROOT : runtimeRoot;
        Path root = absolute(runtimeRoot);
        if (caPath != null) {
            requireInside(root, caPath, "pki.ca-path");
        }
        if (services != null) {
            for (Service service : services) {
                requireInside(root, service.certPath(), "pki.services[" + service.name() + "].cert-path");
                requireInside(root, service.keyPath(), "pki.services[" + service.name() + "].key-path");
            }
        }
    }

    public Service service(String name) {
        return services.stream()
                .filter(service -> service.name().equals(name))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException(
                        "No service named '" + name + "' in pki.services " + names()));
    }

    public List<String> names() {
        return services.stream().map(Service::name).toList();
    }

    public Path runtimeRootPath() {
        return absolute(runtimeRoot);
    }

    /** Normalised absolute form, so {@code ../} escapes cannot hide. */
    public static Path absolute(String path) {
        return Path.of(path).toAbsolutePath().normalize();
    }

    /**
     * Shared by Stage A, which runs before Spring exists and so cannot inject
     * these properties, but must apply the same rule.
     */
    public static Path requireInside(Path root, String candidate, String description) {
        Path resolved = absolute(candidate);
        if (!resolved.startsWith(root)) {
            throw new IllegalStateException(description + " is configured as '" + candidate
                    + "', which resolves to " + resolved + " and is outside pki.runtime-root (" + root
                    + "). Every certificate and key file this application writes must live under that root.");
        }
        return resolved;
    }

    public record Service(String name, String commonName, String certPath, String keyPath) {
    }
}
