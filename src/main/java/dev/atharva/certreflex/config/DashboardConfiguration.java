package dev.atharva.certreflex.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Serves the dashboard at {@code /dashboard}, per spec section 7.
 *
 * <p>Spring Boot's static resource handling only resolves a welcome page for
 * the context root, so {@code /dashboard/} alone would 404 even with
 * {@code static/dashboard/index.html} present. Two explicit forwards are used
 * rather than a trailing-slash redirect: a reviewer typing the URL will not
 * include the slash, and a forward keeps the address bar as typed instead of
 * bouncing them through a 301 that browsers then cache.
 *
 * <p>No catch-all: the SPA has no client-side routing, so there are no deep
 * links to rewrite.
 */
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@Configuration(proxyBeanMethods = false)
public class DashboardConfiguration implements WebMvcConfigurer {

    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/dashboard").setViewName("forward:/dashboard/index.html");
        registry.addViewController("/dashboard/").setViewName("forward:/dashboard/index.html");
    }
}
