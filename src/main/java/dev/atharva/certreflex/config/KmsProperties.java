package dev.atharva.certreflex.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * LocalStack KMS connection details. {@code caKeyId} is written into {@code .env}
 * by {@code scripts/create-ca-key.sh} and read from there at startup.
 */
@ConfigurationProperties(prefix = "aws.kms")
public record KmsProperties(String endpoint, String region, String caKeyId) {

    public String requireCaKeyId() {
        if (caKeyId == null || caKeyId.isBlank()) {
            throw new IllegalStateException(
                    "aws.kms.ca-key-id is not set. Run ./scripts/create-ca-key.sh from the repo root "
                            + "to create the CA key in LocalStack and write CA_KEY_ID into .env.");
        }
        return caKeyId;
    }
}
