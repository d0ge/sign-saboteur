package one.d4d.sessionless.itsdangerous.crypto;

import com.google.common.primitives.Bytes;
import one.d4d.sessionless.itsdangerous.*;
import one.d4d.sessionless.keys.SecretKey;
import one.d4d.sessionless.utils.Utils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

public class TornadoTokenSigner extends TokenSigner{
    public TornadoTokenSigner(SecretKey key) {
        super(key);
    }
    public TornadoTokenSigner() {
        super(Algorithms.SHA1, Derivation.NONE, MessageDerivation.NONE, MessageDigestAlgorithm.NONE,new byte[] {}, new byte[] {}, (byte) '|');
    }
    public TornadoTokenSigner( byte sep) {
        super(new byte[] {}, sep);
    }
    public TornadoTokenSigner( byte[] secret_key, byte sep) {
        super(secret_key, sep);
    }

    @Override
    public byte[] derive_key() throws DerivationException {
        return secret_key;
    }
    @Override
    public boolean verify_signature(byte[] value, byte[] signature) {
        try {
            byte[] expected = get_signature_bytes(value);
            return Arrays.equals(expected, signature);
        }catch (Exception e){
            return false;
        }
    }
    @Override
    public byte[] get_signature_unsafe(byte[] value) throws Exception {
        byte[] key = derive_key();
        SecretKeySpec signingKey = new SecretKeySpec(key, digestMethod.name);
        Mac mac = Mac.getInstance(digestMethod.name);
        mac.init(signingKey);
        return mac.doFinal(value);
    }
    @Override
    public byte[] get_signature(byte[] value) {
        try {
            byte[] key = derive_key();
            SecretKeySpec signingKey = new SecretKeySpec(key, digestMethod.name);
            Mac mac = Mac.getInstance(digestMethod.name);
            mac.init(signingKey);
            return mac.doFinal(value);
        } catch (Exception e) {
            return new byte[] {};
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
            return new byte[] {};
        }
    }

    @Override
    public byte[] unsign(byte[] value) throws BadSignatureException {
        int i = Bytes.lastIndexOf(value, sep);
        // Note! Tornado uses last delimiter for signature calculation.
        byte[] message = Arrays.copyOfRange(value, 0, i+1);
        byte[] signature = Arrays.copyOfRange(value, i+1, value.length);
        byte[] sign = Utils.normalization(signature);
        switch (sign.length) {
            case 28 -> digestMethod = Algorithms.SHA224;
            case 32 -> digestMethod = Algorithms.SHA256;
            case 48 -> digestMethod = Algorithms.SHA384;
            case 64 -> digestMethod = Algorithms.SHA512;
            default -> digestMethod = Algorithms.SHA1;
        }
        if (verify_signature(message, sign))
            return message;
        throw new BadSignatureException("Signature didn't match");
    }
}
