package one.d4d.signsaboteur.itsdangerous.crypto;

import one.d4d.signsaboteur.itsdangerous.Algorithms;
import one.d4d.signsaboteur.itsdangerous.Derivation;
import one.d4d.signsaboteur.itsdangerous.MessageDerivation;
import one.d4d.signsaboteur.itsdangerous.MessageDigestAlgorithm;
import one.d4d.signsaboteur.keys.SecretKey;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.EnumSet;

public class RubyTokenSigner extends TokenSigner {
    public RubyTokenSigner(SecretKey key) {
        super(key);
        this.knownDerivations = EnumSet.of(Derivation.RUBY);
    }

    public RubyTokenSigner(byte[] sep) {
        this(new byte[]{}, sep);
    }

    public RubyTokenSigner(byte[] secret_key, byte[] sep) {
        this(Algorithms.SHA1, Derivation.RUBY, MessageDerivation.NONE, MessageDigestAlgorithm.NONE, secret_key, new byte[]{}, sep);
    }

    public RubyTokenSigner(
            Algorithms digestMethod,
            Derivation keyDerivation,
            MessageDerivation messageDerivation,
            MessageDigestAlgorithm digest,
            byte[] secret_key,
            byte[] salt,
            byte[] sep) {
        super(digestMethod, keyDerivation, messageDerivation, digest, secret_key, salt, sep);
        this.knownDerivations = EnumSet.of(Derivation.RUBY);
    }

    @Override
    public byte[] get_signature_unsafe(byte[] value) throws Exception {
        byte[] key = derive_key();
        SecretKeySpec signingKey = new SecretKeySpec(key, digestMethod.name);
        Mac mac = Mac.getInstance(digestMethod.name);
        mac.init(signingKey);
        return mac.doFinal(value);
    }
}
