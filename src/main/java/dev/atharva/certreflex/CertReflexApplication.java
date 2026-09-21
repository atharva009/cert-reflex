package dev.atharva.certreflex;

import dev.atharva.certreflex.bootstrap.PlaceholderCertificates;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class CertReflexApplication {

    public static void main(String[] args) {
        // Stage A, before the context exists: Tomcat cannot bind an SSL
        // connector whose keystore file is missing. See locked decision 6.
        PlaceholderCertificates.writeMissing();
        SpringApplication.run(CertReflexApplication.class, args);
    }
}
