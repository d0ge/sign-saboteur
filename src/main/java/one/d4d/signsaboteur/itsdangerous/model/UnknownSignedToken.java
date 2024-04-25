package one.d4d.signsaboteur.itsdangerous.model;

import com.nimbusds.jwt.JWTClaimsSet;
import one.d4d.signsaboteur.itsdangerous.Algorithms;
import one.d4d.signsaboteur.itsdangerous.Derivation;
import one.d4d.signsaboteur.itsdangerous.MessageDerivation;
import one.d4d.signsaboteur.itsdangerous.MessageDigestAlgorithm;
import one.d4d.signsaboteur.itsdangerous.crypto.Signers;
import one.d4d.signsaboteur.itsdangerous.crypto.TokenSigner;

public class UnknownSignedToken extends SignedToken {
    public byte[] separator;
    public boolean isURLEncoded = false;

    public UnknownSignedToken(String message, String signature, byte[] separator){
        this(message, signature, separator, false);
    }

    public UnknownSignedToken(String message, String signature, byte[] separator, boolean isURLEncoded) {
        super(message);
        this.signature = signature;
        this.separator = separator;
        this.isURLEncoded = isURLEncoded;
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

    public boolean isURLEncoded() { return isURLEncoded;}
    public String getSignersName() {
        return Signers.UNKNOWN.name();
    }

    public byte[] getSeparator() {
        return separator;
    }
}
