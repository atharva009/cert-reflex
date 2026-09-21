package dev.atharva.certreflex.issuer;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;

import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.MessageType;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

/**
 * A {@link ContentSigner} that holds no private key. Bouncy Castle writes the
 * TBSCertificate bytes into {@link #getOutputStream()}; {@link #getSignature()}
 * hashes them and asks KMS to sign the digest, so the CA key never leaves KMS.
 *
 * <p><strong>Single use.</strong> The accumulated bytes are never reset, so one
 * instance signs exactly one certificate. Construct a new one per signing
 * operation and never register it as a bean: a shared instance would append the
 * next certificate's TBS bytes to the previous one's and sign the concatenation,
 * producing certificates that parse cleanly and fail every signature check.
 */
public final class KmsContentSigner implements ContentSigner {

    /**
     * SHA-256 is fixed in three places that must agree: this algorithm
     * identifier, the digest computed below, and the KMS signing algorithm.
     */
    private static final AlgorithmIdentifier SHA256_WITH_ECDSA =
            new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withECDSA");

    private static final String DIGEST_ALGORITHM = "SHA-256";

    private final KmsClient kms;
    private final String caKeyId;
    private final ByteArrayOutputStream tbsBytes = new ByteArrayOutputStream();

    private boolean used;

    public KmsContentSigner(KmsClient kms, String caKeyId) {
        this.kms = kms;
        this.caKeyId = caKeyId;
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return SHA256_WITH_ECDSA;
    }

    @Override
    public OutputStream getOutputStream() {
        return tbsBytes;
    }

    @Override
    public byte[] getSignature() {
        if (used) {
            throw new IllegalStateException(
                    "KmsContentSigner is single use; construct a new one per certificate");
        }
        used = true;

        SignResponse response = kms.sign(SignRequest.builder()
                .keyId(caKeyId)
                .message(SdkBytes.fromByteArray(digest(tbsBytes.toByteArray())))
                .messageType(MessageType.DIGEST)
                .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256)
                .build());
        // KMS hands back a DER-encoded ECDSA signature (SEQUENCE of r and s),
        // which is exactly the encoding X.509 wants. Returning it untouched is
        // deliberate: re-encoding it to raw/P1363 would produce a certificate
        // that parses fine and fails every signature check.
        return response.signature().asByteArray();
    }

    private static byte[] digest(byte[] input) {
        try {
            return MessageDigest.getInstance(DIGEST_ALGORITHM).digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(DIGEST_ALGORITHM + " is not available", e);
        }
    }
}
