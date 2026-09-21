package dev.atharva.certreflex.spike;

import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;

/**
 * Standalone spike: prove that a certificate signed through KMS, with the CA
 * private key never leaving KMS, verifies as a valid X.509 signature.
 *
 * <p>No Spring, no database. Only {@link KmsContentSigner} is written to be
 * promoted into the issuer package later; the rest of this class is scaffolding.
 */
public final class KmsSigningSpike {

    private static final String KMS_ENDPOINT = "http://localhost:4566";
    private static final Region REGION = Region.US_EAST_1;
    private static final String ISSUER_DN = "CN=cert-reflex intermediate CA";
    private static final String SUBJECT_DN = "CN=demo-a";
    private static final Duration VALIDITY = Duration.ofMinutes(2);
    private static final Path CERT_OUT = Path.of("/tmp/spike-cert.pem");

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        String caKeyId = resolveCaKeyId();
        System.out.println("CA key id:      " + caKeyId);

        try (KmsClient kms = kmsClient()) {
            KeyPair leafKeyPair = generateLeafKeyPair();
            X509Certificate certificate = issue(kms, caKeyId, leafKeyPair);

            System.out.println("Serial:         " + certificate.getSerialNumber().toString(16));
            System.out.println("Subject:        " + certificate.getSubjectX500Principal());
            System.out.println("Issuer:         " + certificate.getIssuerX500Principal());
            System.out.println("Sig algorithm:  " + certificate.getSigAlgName());
            System.out.println("Leaf pubkey:    " + fingerprint(leafKeyPair.getPublic()));

            PublicKey caPublicKey = fetchCaPublicKey(kms, caKeyId);
            System.out.println(verifies(certificate, caPublicKey) ? "PASS" : "FAIL");

            writePem(certificate);
            System.out.println("Wrote:          " + CERT_OUT);
        }
    }

    /** Environment first, then ./.env, so the spike works either way. */
    private static String resolveCaKeyId() throws IOException {
        String fromEnv = System.getenv("CA_KEY_ID");
        if (fromEnv != null && !fromEnv.isBlank()) {
            return fromEnv.trim();
        }
        Path dotEnv = Path.of(".env");
        if (Files.isReadable(dotEnv)) {
            for (String line : Files.readAllLines(dotEnv)) {
                if (line.startsWith("CA_KEY_ID=")) {
                    String value = line.substring("CA_KEY_ID=".length()).trim();
                    if (!value.isBlank()) {
                        return value;
                    }
                }
            }
        }
        System.err.println("""
                CA_KEY_ID is not set.

                Export it, or run ./scripts/create-ca-key.sh from the repo root to
                create the CA key in LocalStack and write CA_KEY_ID into ./.env.
                This spike must be run from the repo root for ./.env to be found.""");
        System.exit(1);
        throw new IllegalStateException("unreachable");
    }

    private static KmsClient kmsClient() {
        // LocalStack accepts any credentials, but without a provider the SDK
        // walks its whole default chain looking for real ones and fails.
        return KmsClient.builder()
                .endpointOverride(URI.create(KMS_ENDPOINT))
                .region(REGION)
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create("test", "test")))
                .build();
    }

    private static KeyPair generateLeafKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        generator.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
        return generator.generateKeyPair();
    }

    private static X509Certificate issue(KmsClient kms, String caKeyId, KeyPair leafKeyPair) throws Exception {
        Instant notBefore = Instant.now();
        Instant notAfter = notBefore.plus(VALIDITY);

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                new X500Name(ISSUER_DN),
                randomSerial(),
                Date.from(notBefore),
                Date.from(notAfter),
                new X500Name(SUBJECT_DN),
                leafKeyPair.getPublic());

        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        builder.addExtension(Extension.extendedKeyUsage, false,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
        // Reviewers connect to https://localhost:8443, so "localhost" has to be
        // present or hostname verification fails for any client not passing -k.
        builder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(
                List.of(new GeneralName(GeneralName.dNSName, "localhost"),
                        new GeneralName(GeneralName.dNSName, "demo-a"))
                        .toArray(new GeneralName[0])));

        X509CertificateHolder holder = builder.build(new KmsContentSigner(kms, caKeyId));
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(holder);
    }

    private static BigInteger randomSerial() {
        return new BigInteger(128, new SecureRandom()).abs().add(BigInteger.ONE);
    }

    private static PublicKey fetchCaPublicKey(KmsClient kms, String caKeyId) throws Exception {
        GetPublicKeyResponse response = kms.getPublicKey(
                GetPublicKeyRequest.builder().keyId(caKeyId).build());
        // KMS returns a DER SubjectPublicKeyInfo, which is what X509EncodedKeySpec takes.
        return KeyFactory.getInstance("EC")
                .generatePublic(new X509EncodedKeySpec(response.publicKey().asByteArray()));
    }

    private static boolean verifies(X509Certificate certificate, PublicKey caPublicKey) {
        try {
            certificate.verify(caPublicKey);
            return true;
        } catch (Exception e) {
            System.err.println("Signature verification failed: " + e);
            return false;
        }
    }

    private static String fingerprint(PublicKey publicKey) throws Exception {
        byte[] sha256 = java.security.MessageDigest.getInstance("SHA-256").digest(publicKey.getEncoded());
        return HexFormat.of().formatHex(sha256);
    }

    private static void writePem(X509Certificate certificate) throws IOException {
        try (JcaPEMWriter writer = new JcaPEMWriter(new FileWriter(CERT_OUT.toFile()))) {
            writer.writeObject(certificate);
        }
    }
}
