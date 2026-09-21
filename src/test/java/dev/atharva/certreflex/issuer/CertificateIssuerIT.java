package dev.atharva.certreflex.issuer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.Comparator;
import java.util.List;

import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.localstack.LocalStackContainer;
import org.testcontainers.postgresql.PostgreSQLContainer;

import dev.atharva.certreflex.config.PkiProperties;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.CreateKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.KeySpec;
import software.amazon.awssdk.services.kms.model.KeyUsageType;

/**
 * Issues certificates against a real KMS API. Nothing is mocked: the signature
 * is produced by LocalStack's KMS and verified against the public key KMS
 * reports, which is the whole reason LocalStack is in this project.
 *
 * <p>Postgres is here only because the application context needs a datasource;
 * no test below touches the database.
 */
@SpringBootTest
@Testcontainers
class CertificateIssuerIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    @Container
    static final LocalStackContainer LOCALSTACK =
            new LocalStackContainer("localstack/localstack:4.14").withServices("kms");

    /** The CA certificate cache must never land on the developer's ./runtime/ca.pem. */
    private static final Path CA_CACHE_DIR = createTempDirectory();

    private static String caKeyId;

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("aws.kms.endpoint", () -> LOCALSTACK.getEndpoint().toString());
        registry.add("aws.kms.region", LOCALSTACK::getRegion);
        registry.add("aws.kms.ca-key-id", CertificateIssuerIT::caKeyId);
        registry.add("pki.ca-path", () -> CA_CACHE_DIR.resolve("ca.pem").toString());
    }

    /**
     * Same parameters as scripts/create-ca-key.sh. Memoized because a dynamic
     * property supplier can be invoked more than once, and each call would
     * otherwise mint another CA key.
     */
    private static synchronized String caKeyId() {
        if (caKeyId == null) {
            try (KmsClient kms = testKmsClient()) {
                caKeyId = kms.createKey(CreateKeyRequest.builder()
                        .keyUsage(KeyUsageType.SIGN_VERIFY)
                        .keySpec(KeySpec.ECC_NIST_P256)
                        .description("cert-reflex intermediate signing key")
                        .build())
                        .keyMetadata().keyId();
            }
        }
        return caKeyId;
    }

    private static KmsClient testKmsClient() {
        return KmsClient.builder()
                .endpointOverride(URI.create(LOCALSTACK.getEndpoint().toString()))
                .region(Region.of(LOCALSTACK.getRegion()))
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create(LOCALSTACK.getAccessKey(), LOCALSTACK.getSecretKey())))
                .build();
    }

    @Autowired
    private CertificateIssuer issuer;

    @Autowired
    private CertificateAuthority certificateAuthority;

    @Autowired
    private PkiProperties pkiProperties;

    @Autowired
    private KmsClient kmsClient;

    @Test
    void signatureVerifiesAgainstTheCaPublicKeyFromKms() throws Exception {
        IssuedCertificate issued = issuer.issue("demo-a");

        byte[] spki = kmsClient.getPublicKey(GetPublicKeyRequest.builder().keyId(caKeyId()).build())
                .publicKey().asByteArray();
        PublicKey caPublicKey = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(spki));

        issued.certificate().verify(caPublicKey);
        issued.caCertificate().verify(caPublicKey);
    }

    @Test
    void validityWindowIsBackdatedAndLastsTheConfiguredLifetime() {
        IssuedCertificate issued = issuer.issue("demo-a");
        X509Certificate certificate = issued.certificate();

        // Asserted as a relationship between the two fields, never against
        // wall-clock now, which would make this flaky.
        Duration window = Duration.between(
                certificate.getNotBefore().toInstant(), certificate.getNotAfter().toInstant());
        assertThat(window).isEqualTo(pkiProperties.certValidity().plusSeconds(30));
        assertThat(issued.notBefore()).isEqualTo(certificate.getNotBefore().toInstant());
        assertThat(issued.notAfter()).isEqualTo(certificate.getNotAfter().toInstant());
    }

    @Test
    void subjectAlternativeNameCoversLocalhostAndTheServiceName() throws Exception {
        X509Certificate certificate = issuer.issue("demo-b").certificate();

        List<String> names = certificate.getSubjectAlternativeNames().stream()
                .map(entry -> (String) entry.get(1))
                .toList();
        assertThat(names).containsExactlyInAnyOrder("localhost", "demo-b");
    }

    @Test
    void keyUsageIsDigitalSignatureOnly() {
        X509Certificate certificate = issuer.issue("demo-a").certificate();

        // The full array, so a reintroduced keyEncipherment fails here:
        // digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment,
        // keyAgreement, keyCertSign, cRLSign, encipherOnly, decipherOnly.
        assertThat(certificate.getKeyUsage()).containsExactly(
                true, false, false, false, false, false, false, false, false);
    }

    @Test
    void isALeafForServerAuthentication() throws Exception {
        X509Certificate certificate = issuer.issue("demo-a").certificate();

        assertThat(certificate.getExtendedKeyUsage()).containsExactly("1.3.6.1.5.5.7.3.1");
        assertThat(certificate.getBasicConstraints()).isEqualTo(-1);
    }

    @Test
    void authorityKeyIdentifierPointsAtTheCaSubjectKeyIdentifier() throws Exception {
        IssuedCertificate issued = issuer.issue("demo-a");

        byte[] authorityKeyId = AuthorityKeyIdentifier
                .getInstance(parseExtension(issued.certificate(), Extension.authorityKeyIdentifier))
                .getKeyIdentifier();
        byte[] subjectKeyId = SubjectKeyIdentifier
                .getInstance(parseExtension(issued.caCertificate(), Extension.subjectKeyIdentifier))
                .getKeyIdentifier();

        assertThat(authorityKeyId).isEqualTo(subjectKeyId);
    }

    @Test
    void leafChainsToTheCaCertificate() throws Exception {
        IssuedCertificate issued = issuer.issue("demo-a");
        X509Certificate ca = certificateAuthority.certificate();

        issued.certificate().verify(ca.getPublicKey());
        assertThat(issued.certificate().getIssuerX500Principal()).isEqualTo(ca.getSubjectX500Principal());
        assertThat(ca.getBasicConstraints()).isGreaterThanOrEqualTo(0);
    }

    @Test
    void eachIssuanceGetsItsOwnSerialAndKeyPair() {
        IssuedCertificate first = issuer.issue("demo-a");
        IssuedCertificate second = issuer.issue("demo-a");

        assertThat(first.serialNumber()).isNotEqualTo(second.serialNumber());
        assertThat(first.certificate().getPublicKey().getEncoded())
                .isNotEqualTo(second.certificate().getPublicKey().getEncoded());
        assertThat(first.privateKeyPem()).isNotEqualTo(second.privateKeyPem());
    }

    @Test
    void signerRefusesToSignTwice() {
        KmsContentSigner signer = new KmsContentSigner(kmsClient, caKeyId());

        assertThat(signer.getSignature()).isNotEmpty();
        assertThatIllegalStateException()
                .isThrownBy(signer::getSignature)
                .withMessageContaining("single use");
    }

    private static org.bouncycastle.asn1.ASN1Primitive parseExtension(
            X509Certificate certificate, org.bouncycastle.asn1.ASN1ObjectIdentifier oid) throws IOException {
        return JcaX509ExtensionUtils.parseExtensionValue(certificate.getExtensionValue(oid.getId()));
    }

    private static Path createTempDirectory() {
        try {
            return Files.createTempDirectory("cert-reflex-ca");
        } catch (IOException e) {
            throw new IllegalStateException("Could not create a temp directory for the CA cache", e);
        }
    }

    @AfterAll
    static void deleteCaCache() throws IOException {
        try (var paths = Files.walk(CA_CACHE_DIR)) {
            paths.sorted(Comparator.reverseOrder()).forEach(path -> path.toFile().delete());
        }
    }
}
