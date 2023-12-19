package one.d4d.sessionless.itsdangerous.crypto;

import one.d4d.sessionless.itsdangerous.Algorithms;
import one.d4d.sessionless.itsdangerous.Derivation;
import one.d4d.sessionless.itsdangerous.DerivationException;
import one.d4d.sessionless.itsdangerous.MessageDigestAlgorithm;
import one.d4d.sessionless.utils.Utils;
import one.d4d.sessionless.keys.SecretKey;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class OauthProxyTokenSigner extends TokenSigner{
    public OauthProxyTokenSigner(SecretKey key) {
        super(key);
    }
    public OauthProxyTokenSigner() {
        super(Algorithms.SHA256, Derivation.NONE, MessageDigestAlgorithm.NONE, new byte[] {}, new byte[] {}, (byte)'|');
    }
    public OauthProxyTokenSigner(Algorithms digestMethod, byte[] secret_key, byte sep) {
        super(digestMethod, Derivation.NONE, MessageDigestAlgorithm.NONE, secret_key, new byte[] {}, sep);
    }
    @Override
    public byte[] derive_key() throws DerivationException {
        return secret_key;
    }
    @Override
    public byte[] get_signature_bytes(byte[] value) {
        try {
            byte[][] data = Utils.split(value, sep);
            byte[] key = derive_key();
            SecretKeySpec signingKey = new SecretKeySpec(key, digestMethod.name);
            Mac mac = Mac.getInstance(digestMethod.name);
            mac.init(signingKey);
            for(byte[] d: data) {
                mac.update(d);
            }
            return mac.doFinal();
        } catch (Exception e) {
            return new byte[] {};
        }
    }
    @Override
    public byte[] get_signature_unsafe(byte[] value) throws Exception {
        byte[][] data = Utils.split(value, sep);
        byte[] key = derive_key();
        SecretKeySpec signingKey = new SecretKeySpec(key, digestMethod.name);
        Mac mac = Mac.getInstance(digestMethod.name);
        mac.init(signingKey);
        for(byte[] d: data) {
            mac.update(d);
        }
        byte[] sig = mac.doFinal();
        return Base64.getUrlEncoder().withoutPadding().encode(sig);
    }
}
