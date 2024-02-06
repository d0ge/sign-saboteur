package one.d4d.sessionless.itsdangerous.crypto;

import one.d4d.sessionless.itsdangerous.*;
import one.d4d.sessionless.keys.SecretKey;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.EnumSet;

public class ExpressTokenSigner extends TokenSigner {
    public ExpressTokenSigner(SecretKey key) {
        super(key);
        this.knownDerivations = EnumSet.of(Derivation.NONE);
    }

    public ExpressTokenSigner() {
        this(Algorithms.SHA1, Derivation.NONE, MessageDerivation.NONE, MessageDigestAlgorithm.NONE, new byte[]{}, new byte[]{}, new byte[]{});
    }

    public ExpressTokenSigner(
            Algorithms digestMethod,
            Derivation keyDerivation,
            MessageDerivation messageDerivation,
            MessageDigestAlgorithm digest,
            byte[] secret_key,
            byte[] salt,
            byte[] sep) {
        super(digestMethod, keyDerivation, messageDerivation, digest, secret_key, salt, sep);
        this.knownDerivations = EnumSet.of(Derivation.NONE);
    }

    public ExpressTokenSigner(byte[] secret_key, byte[] sep) {
        super(secret_key, sep);
    }

    @Override
    public byte[] derive_key() throws DerivationException {
        return secret_key;
    }

    @Override
    public byte[] get_signature(byte[] value) {
        try {
            byte[] key = derive_key();
            SecretKeySpec signingKey = new SecretKeySpec(key, digestMethod.name);
            Mac mac = Mac.getInstance(digestMethod.name);
            mac.init(signingKey);
            byte[] sig = mac.doFinal(value);
            return Base64.getUrlEncoder().withoutPadding().encode(sig);
        } catch (Exception e) {
            return new byte[]{};
        }
    }

    @Override
    public byte[] get_signature_bytes(byte[] value) {
        try {
            byte[] key = derive_key();
            SecretKeySpec signingKey = new SecretKeySpec(key, digestMethod.name);
            Mac mac = Mac.getInstance(digestMethod.name);
            mac.init(signingKey);
            return mac.doFinal(value);
        } catch (Exception e) {
            return new byte[]{};
        }
    }

}
