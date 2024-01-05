package one.d4d.sessionless.itsdangerous.crypto;

import one.d4d.sessionless.itsdangerous.Algorithms;
import one.d4d.sessionless.itsdangerous.Derivation;
import one.d4d.sessionless.itsdangerous.MessageDerivation;
import one.d4d.sessionless.itsdangerous.MessageDigestAlgorithm;
import one.d4d.sessionless.keys.SecretKey;

public class DjangoTokenSigner extends DangerousTokenSigner {

    public DjangoTokenSigner(SecretKey key) {
        super(key);
    }

    public DjangoTokenSigner(byte sep) {
        super(sep);
    }

    public DjangoTokenSigner(byte[] secret_key, byte sep) {
        super(secret_key, sep);
    }

    public DjangoTokenSigner(Algorithms digestMethod, Derivation keyDerivation, byte[] secret_key, byte[] salt, byte sep) {
        super(digestMethod, keyDerivation, secret_key, salt, sep);
    }

    public DjangoTokenSigner(String digestMethod, String keyDerivation, byte[] secret_key, byte[] salt, byte sep) {
        super(digestMethod, keyDerivation, secret_key, salt, sep);
    }
    public DjangoTokenSigner(
            Algorithms algorithm,
            Derivation keyDerivation,
            MessageDerivation messageDerivation,
            MessageDigestAlgorithm digest,
            byte[] secret_key,
            byte[] salt,
            byte sep) {
        super(algorithm, keyDerivation, messageDerivation, digest, secret_key, salt, sep);
    }
}
