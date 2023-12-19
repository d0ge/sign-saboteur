package one.d4d.sessionless.itsdangerous.model;

import com.nimbusds.jwt.JWTClaimsSet;
import one.d4d.sessionless.itsdangerous.crypto.TokenSigner;

public abstract class SignedToken {
    public String message;
    public String signature;
    public TokenSigner signer;


    public SignedToken(String message) {
        this.message = message;
    }

    public TokenSigner getSigner() {
        return signer;
    }

    public void setSigner(TokenSigner signer) {
        this.signer = signer;
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
