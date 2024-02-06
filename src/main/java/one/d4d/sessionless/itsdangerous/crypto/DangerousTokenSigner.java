package one.d4d.sessionless.itsdangerous.crypto;

import com.google.common.primitives.Bytes;
import one.d4d.sessionless.itsdangerous.*;
import one.d4d.sessionless.keys.SecretKey;
import one.d4d.sessionless.utils.Utils;

import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;

public class DangerousTokenSigner extends TokenSigner {

    public DangerousTokenSigner(SecretKey key) {
        super(key);
        this.knownDerivations = EnumSet.of(Derivation.HMAC);
    }

    public DangerousTokenSigner(byte[] sep) {
        this(Algorithms.SHA1, Derivation.HMAC, MessageDerivation.NONE, MessageDigestAlgorithm.SHA256, new byte[]{}, new byte[]{}, sep);
    }

    public DangerousTokenSigner(byte[] secret_key, byte[] salt, byte[] sep) {
        this(Algorithms.SHA1, Derivation.HMAC, MessageDerivation.NONE, MessageDigestAlgorithm.SHA256, secret_key, salt, sep);
    }

    public DangerousTokenSigner(
            Algorithms algorithm,
            Derivation keyDerivation,
            MessageDerivation messageDerivation,
            MessageDigestAlgorithm digest,
            byte[] secret_key,
            byte[] salt,
            byte[] sep) {
        super(algorithm, keyDerivation, messageDerivation, digest, secret_key, salt, sep);
        this.knownDerivations = EnumSet.of(Derivation.CONCAT, Derivation.DJANGO, Derivation.HMAC, Derivation.NONE);
    }


    public byte[] unsign(byte[] value) throws BadSignatureException {
        int i = Collections.lastIndexOfSubList(Bytes.asList(value), Bytes.asList(sep));
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
