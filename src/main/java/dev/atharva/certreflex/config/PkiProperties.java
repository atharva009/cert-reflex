package dev.atharva.certreflex.config;

import java.time.Duration;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Certificate lifecycle timings and the list of services this system manages.
 *
 * <p>The service list is the single definition of the managed fleet: bootstrap,
 * the demo listeners, the watcher and the remediator all read it from here.
 */
@ConfigurationProperties(prefix = "pki")
public record PkiProperties(
        Duration certValidity,
        Duration rotateThreshold,
        Duration watcherInterval,
        List<Service> services) {

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

    public record Service(String name, String commonName, String certPath, String keyPath) {
    }
}
