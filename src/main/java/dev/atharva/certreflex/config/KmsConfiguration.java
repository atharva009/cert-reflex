package dev.atharva.certreflex.config;

import java.net.URI;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;

@Configuration(proxyBeanMethods = false)
public class KmsConfiguration {

    @Bean
    KmsClient kmsClient(KmsProperties properties) {
        // LocalStack accepts any credentials, but without a provider the SDK
        // walks its whole default chain looking for real ones and fails.
        return KmsClient.builder()
                .endpointOverride(URI.create(properties.endpoint()))
                .region(Region.of(properties.region()))
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create("test", "test")))
                .build();
    }
}
