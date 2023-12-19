package one.d4d.sessionless.itsdangerous.crypto;

import com.google.common.primitives.Bytes;
import one.d4d.sessionless.itsdangerous.Algorithms;
import one.d4d.sessionless.itsdangerous.BadSignatureException;
import one.d4d.sessionless.itsdangerous.Derivation;
import one.d4d.sessionless.itsdangerous.MessageDigestAlgorithm;
import one.d4d.sessionless.keys.SecretKey;
import one.d4d.sessionless.utils.Utils;

import java.util.Arrays;

public class DangerousTokenSigner extends TokenSigner {

    public DangerousTokenSigner(SecretKey key) {
        super(key);
    }

    public DangerousTokenSigner(byte sep) {
        super(Algorithms.SHA1, Derivation.HMAC, new byte[]{}, new byte[]{}, sep);
    }

    public DangerousTokenSigner(byte[] secret_key, byte sep) {
        super(secret_key, sep);
    }

    public DangerousTokenSigner(Algorithms digestMethod, Derivation keyDerivation, byte[] secret_key, byte[] salt, byte sep) {
        super(digestMethod, keyDerivation, secret_key, salt, sep);
    }

    public DangerousTokenSigner(
            Algorithms algorithm,
            Derivation keyDerivation,
            MessageDigestAlgorithm digest,
            byte[] secret_key,
            byte[] salt,
            byte sep) {
        super(algorithm, keyDerivation, digest, secret_key, salt, sep);
    }

    public DangerousTokenSigner(String digestMethod, String keyDerivation, byte[] secret_key, byte[] salt, byte sep) {
        super(Algorithms.valueOf(digestMethod), Derivation.valueOf(keyDerivation), secret_key, salt, sep);
    }

    public byte[] unsign(byte[] value) throws BadSignatureException {
        int i = Bytes.lastIndexOf(value, sep);
        byte[] message = Arrays.copyOfRange(value, 0, i);
        byte[] signature = Arrays.copyOfRange(value, i + 1, value.length);
        return fast_unsign(message, signature);
    }

    public byte[] fast_unsign(byte[] message, byte[] signature) throws BadSignatureException {
        byte[] sign = Utils.normalization(signature);
        // Signature length in bytes
        switch (sign.length) {
            case 28 -> digestMethod = Algorithms.SHA224;
            case 32 -> digestMethod = Algorithms.SHA256;
            case 48 -> digestMethod = Algorithms.SHA384;
            case 64 -> digestMethod = Algorithms.SHA512;
            default -> digestMethod = Algorithms.SHA1;
        }
        if (verify_signature_bytes(message, sign))
            return message;
        throw new BadSignatureException("Signature didn't match");
    }
}
