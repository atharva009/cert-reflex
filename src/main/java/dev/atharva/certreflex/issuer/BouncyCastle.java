package dev.atharva.certreflex.issuer;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * One shared Bouncy Castle provider instance, passed explicitly wherever it is
 * needed rather than installed into the JVM with {@code Security.addProvider}.
 * Global registration is order-dependent, and beans that build certificates
 * during context startup can easily run before whatever would have registered it.
 */
final class BouncyCastle {

    static final BouncyCastleProvider PROVIDER = new BouncyCastleProvider();

    private BouncyCastle() {
    }
}
