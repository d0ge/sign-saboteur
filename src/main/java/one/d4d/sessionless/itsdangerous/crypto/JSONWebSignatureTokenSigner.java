package one.d4d.sessionless.itsdangerous.crypto;

import one.d4d.sessionless.itsdangerous.Algorithms;
import one.d4d.sessionless.itsdangerous.Derivation;
import one.d4d.sessionless.itsdangerous.MessageDerivation;
import one.d4d.sessionless.itsdangerous.MessageDigestAlgorithm;
import one.d4d.sessionless.keys.SecretKey;

public class JSONWebSignatureTokenSigner extends TokenSigner {
    public JSONWebSignatureTokenSigner(SecretKey key) {
        super(key);
        this.keyDerivation = Derivation.NONE;
        this.messageDigestAlgorithm = MessageDigestAlgorithm.NONE;
    }

    public JSONWebSignatureTokenSigner(byte sep) {
        super(Algorithms.SHA256, Derivation.NONE, MessageDerivation.NONE, MessageDigestAlgorithm.NONE, new byte[]{}, new byte[]{}, sep);
    }
}
