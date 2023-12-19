package one.d4d.sessionless.itsdangerous.model;

import com.nimbusds.jwt.JWTClaimsSet;
import one.d4d.sessionless.itsdangerous.BadSignatureException;
import one.d4d.sessionless.itsdangerous.crypto.ExpressTokenSigner;
import one.d4d.sessionless.utils.Utils;

import java.util.Base64;

public class ExpressSignedToken extends SignedToken {
    public byte separator = 0;
    public String parameter;
    public String payload;

    public ExpressSignedToken(String parameter, String payload, String signature) {
        super(String.format("%s=%s", parameter, payload));
        this.parameter = parameter;
        this.payload = payload;
        this.signature = signature;
        this.signer = new ExpressTokenSigner();
    }


    public void setSigner(ExpressTokenSigner signer) {
        this.signer = signer;
    }


    public void unsign() throws BadSignatureException {
        signer.fast_unsign(getEncodedMessage().getBytes(), this.signature.getBytes());
    }

    public String getParameter() {
        return parameter;
    }

    public String getPayload() {
        try {
            byte[] json = Utils.base64Decompress(this.payload.getBytes());
            return new String(json);
        } catch (Exception e) {
            return payload;
        }
    }

    public byte[] getSeparator() {
        return new byte[]{separator};
    }

    @Override
    public String serialize() {
        return String.format("%s", payload);
    }

    @Override
    public void resign() throws Exception {
        byte[] value = message.getBytes();
        this.signature = new String(signer.get_signature_unsafe(value));
    }

    @Override
    public void setClaims(JWTClaimsSet claims) {
        this.payload = new String(Base64.getUrlEncoder().encode(claims.toString().getBytes()));
        this.message = String.format("%s=%s", parameter, payload);
    }
}
