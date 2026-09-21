package dev.atharva.certreflex.issuer;

import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.ssl.pem.PemSslStoreBundle;
import org.springframework.boot.ssl.pem.PemSslStoreDetails;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

/**
 * Temporary: issues one certificate so this code is verifiable with openssl
 * before the integration test exists. Deleted once the test lands.
 */
@Profile("issuer-check")
@Component
class IssuerCheckRunner implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(IssuerCheckRunner.class);

    private static final Path CHAIN_OUT = Path.of("/tmp/issued-chain.pem");
    private static final Path CA_OUT = Path.of("/tmp/issued-ca.pem");
    private static final Path KEY_OUT = Path.of("/tmp/issued-key.pem");

    private final CertificateIssuer issuer;

    IssuerCheckRunner(CertificateIssuer issuer) {
        this.issuer = issuer;
    }

    @Override
    public void run(String... args) throws Exception {
        IssuedCertificate issued = issuer.issue("demo-a");

        Pem.writeAtomically(CHAIN_OUT, issued.chainPem());
        Pem.writeAtomically(CA_OUT, Pem.encode(issued.caCertificate()));
        Pem.writeAtomically(KEY_OUT, issued.privateKeyPem());

        System.out.println("serial:     " + issued.serialHex());
        System.out.println("subject:    " + issued.certificate().getSubjectX500Principal());
        System.out.println("issuer:     " + issued.certificate().getIssuerX500Principal());
        System.out.println("not_before: " + issued.notBefore());
        System.out.println("not_after:  " + issued.notAfter());
        System.out.println("leaf key:   " + fingerprint(issued));
        System.out.println("wrote:      " + CHAIN_OUT + ", " + CA_OUT + ", " + KEY_OUT);

        checkBundleParsesChain(issued);
    }

    /**
     * The chain PEM is what a listener's cert.pem will hold, so confirm Spring's
     * PEM store bundle treats the first certificate as the leaf and pairs it
     * with the private key.
     */
    private void checkBundleParsesChain(IssuedCertificate issued) {
        try {
            PemSslStoreDetails details = PemSslStoreDetails
                    .forCertificate("file:" + CHAIN_OUT)
                    .withPrivateKey("file:" + KEY_OUT);
            KeyStore keyStore = new PemSslStoreBundle(details, null).getKeyStore();

            for (Enumeration<String> aliases = keyStore.aliases(); aliases.hasMoreElements(); ) {
                String alias = aliases.nextElement();
                Certificate[] chain = keyStore.getCertificateChain(alias);
                X509Certificate first = (X509Certificate) chain[0];
                boolean leafFirst = first.getSerialNumber().equals(issued.serialNumber());
                boolean keyPresent = keyStore.getKey(alias, new char[0]) != null;
                System.out.println("bundle:     alias=" + alias + " chain_length=" + chain.length
                        + " first_is_leaf=" + leafFirst + " private_key_paired=" + keyPresent);
            }
        } catch (Exception e) {
            log.error("PemSslStoreBundle could not parse the issued chain", e);
        }
    }

    private static String fingerprint(IssuedCertificate issued) throws Exception {
        byte[] sha256 = java.security.MessageDigest.getInstance("SHA-256")
                .digest(issued.certificate().getPublicKey().getEncoded());
        return java.util.HexFormat.of().formatHex(sha256);
    }
}
