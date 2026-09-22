package dev.atharva.certreflex.demo;

import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import dev.atharva.certreflex.issuer.Serials;
import jakarta.servlet.http.HttpServletRequest;

/**
 * What this listener is actually serving.
 *
 * <p>Answers from the connector's own live SSL configuration, not from the SSL
 * bundle (locked decision 15: reading the bundle throws once the file on disk
 * is garbage) and not from the inventory. The whole point of this endpoint is
 * to be an independent witness to what the wire carries, so that the dashboard
 * can be checked against it rather than confirming itself.
 */
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@RestController
class DemoController {

    private final DemoListeners listeners;

    DemoController(DemoListeners listeners) {
        this.listeners = listeners;
    }

    @GetMapping("/")
    Response serving(HttpServletRequest request) {
        int port = request.getLocalPort();
        return listeners.forPort(port)
                .map(listener -> new Response(
                        listener.serviceName(),
                        port,
                        listeners.currentCertificate(listener)
                                .map(certificate -> Serials.hex(certificate.getSerialNumber()))
                                .orElse("unknown")))
                .orElseGet(() -> new Response("cert-reflex", port, notApplicable()));
    }

    private static String notApplicable() {
        return "n/a (plain HTTP)";
    }

    record Response(String service, int port, String serial) {
    }
}
