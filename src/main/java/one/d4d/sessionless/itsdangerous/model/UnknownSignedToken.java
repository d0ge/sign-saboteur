package one.d4d.sessionless.itsdangerous.model;

import com.nimbusds.jwt.JWTClaimsSet;
import one.d4d.sessionless.itsdangerous.crypto.TokenSigner;

public class UnknownSignedToken extends SignedToken {
    public byte separator;

    public UnknownSignedToken(String message, String signature, byte separator) {
        super(message);
        this.signature = signature;
        this.separator = separator;
        this.signer = new TokenSigner(new byte[]{}, separator);
    }


    @Override
    public String serialize() {
        return String.format("%s%c%s", message, separator, signature);
    }

    @Override
    public void resign() throws Exception {
        this.signature = new String(signer.get_signature_unsafe(message.getBytes()));
    }

    @Override
    public void setClaims(JWTClaimsSet claims) {

    }
}
