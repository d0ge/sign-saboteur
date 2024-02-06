package one.d4d.sessionless.itsdangerous.crypto;

import one.d4d.sessionless.itsdangerous.*;
import one.d4d.sessionless.keys.SecretKey;
import one.d4d.sessionless.utils.Utils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.EnumSet;

public class OauthProxyTokenSigner extends TokenSigner {
    public OauthProxyTokenSigner(SecretKey key) {
        super(key);
        this.knownDerivations = EnumSet.of(Derivation.NONE);
    }

    public OauthProxyTokenSigner() {
        this(new byte[]{}, new byte[]{'|'});
    }

    public OauthProxyTokenSigner(byte[] secret_key, byte[] sep) {
        this(Algorithms.SHA256, Derivation.NONE, MessageDerivation.NONE, MessageDigestAlgorithm.NONE, secret_key, new byte[]{}, sep);
    }

    public OauthProxyTokenSigner(
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

    @Override
    public byte[] derive_key() throws DerivationException {
        return secret_key;
    }

    @Override
    public byte[] get_signature_unsafe(byte[] value) throws Exception {
        byte[][] data = Utils.split(value, sep);
        byte[] key = derive_key();
        SecretKeySpec signingKey = new SecretKeySpec(key, digestMethod.name);
        Mac mac = Mac.getInstance(digestMethod.name);
        mac.init(signingKey);
        for (byte[] d : data) {
            mac.update(d);
        }
        byte[] sig = mac.doFinal();
        return Base64.getUrlEncoder().withoutPadding().encode(sig);
    }

    @Override
    public byte[] get_signature_bytes(byte[] value) {
        try {
            byte[][] data = Utils.split(value, sep);
            byte[] key = derive_key();
            SecretKeySpec signingKey = new SecretKeySpec(key, digestMethod.name);
            Mac mac = Mac.getInstance(digestMethod.name);
            mac.init(signingKey);
            for (byte[] d : data) {
                mac.update(d);
            }
            return mac.doFinal();
        } catch (Exception e) {
            return new byte[]{};
        }
    }
}
