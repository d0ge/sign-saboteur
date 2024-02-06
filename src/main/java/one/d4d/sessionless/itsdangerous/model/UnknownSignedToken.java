package one.d4d.sessionless.itsdangerous.model;

import burp.config.Signers;
import com.nimbusds.jwt.JWTClaimsSet;
import one.d4d.sessionless.itsdangerous.Algorithms;
import one.d4d.sessionless.itsdangerous.Derivation;
import one.d4d.sessionless.itsdangerous.MessageDerivation;
import one.d4d.sessionless.itsdangerous.MessageDigestAlgorithm;
import one.d4d.sessionless.itsdangerous.crypto.TokenSigner;

public class UnknownSignedToken extends SignedToken {
    public byte[] separator;

    public UnknownSignedToken(String message, String signature, byte[] separator) {
        super(message);
        this.signature = signature;
        this.separator = separator;
        this.signer = new TokenSigner(
                Algorithms.SHA256,
                Derivation.NONE,
                MessageDerivation.NONE,
                MessageDigestAlgorithm.NONE,
                new byte[]{},
                new byte[]{},
                separator);
    }


    @Override
    public String serialize() {
        return String.format("%s%s%s", message, new String(separator), signature);
    }

    @Override
    public void resign() throws Exception {
        this.signature = new String(signer.get_signature_unsafe(message.getBytes()));
    }

    @Override
    public void setClaims(JWTClaimsSet claims) {

    }

    public String getSignersName() {
        return Signers.UNKNOWN.name();
    }

    public byte[] getSeparator() {
        return separator;
    }
}
