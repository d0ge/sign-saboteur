package one.d4d.signsaboteur.itsdangerous.model;

import com.nimbusds.jwt.JWTClaimsSet;
import one.d4d.signsaboteur.itsdangerous.crypto.TokenSigner;
import one.d4d.signsaboteur.keys.SecretKey;

public abstract class SignedToken {
    public String message;
    public String signature;
    public TokenSigner signer;
    private SecretKey key;

    public SignedToken(String message) {
        this.message = message;
    }

    public TokenSigner getSigner() {
        return signer;
    }

    public void setSigner(TokenSigner signer) {
        this.signer = signer;
    }

    public SecretKey getKey() {
        return key;
    }

    public void setKey(SecretKey key) {
        this.key = key;
    }

    public String getEncodedMessage() {
        return message;
    }

    public abstract String serialize();

    public abstract void resign() throws Exception;
    public abstract void setClaims(JWTClaimsSet claims);

    public String getEncodedSignature() {
        return signature;
    }

    public byte[] getSignature() {
        return signature.getBytes();
    }
}
