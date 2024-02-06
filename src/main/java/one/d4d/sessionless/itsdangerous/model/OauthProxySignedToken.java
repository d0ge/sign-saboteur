package one.d4d.sessionless.itsdangerous.model;

import com.nimbusds.jwt.JWTClaimsSet;
import one.d4d.sessionless.itsdangerous.BadSignatureException;
import one.d4d.sessionless.itsdangerous.crypto.OauthProxyTokenSigner;
import one.d4d.sessionless.utils.Utils;

import java.util.Base64;

public class OauthProxySignedToken extends SignedToken {
    public static byte[] separator = {'|'};
    public String parameter;
    public String payload;
    public String timestamp;


    public OauthProxySignedToken(String parameter, String payload, String timestamp, String signature) {
        super(String.format("%s%s%s%s%s", parameter, new String(separator), payload, new String(separator), timestamp));
        this.payload = payload;
        this.timestamp = timestamp;
        this.signature = signature;
        this.parameter = parameter;
        this.signer = new OauthProxyTokenSigner();
    }

    public String getParameter() {
        return parameter;
    }

    public String getPayload() {
        return payload;
    }

    public String getTimestamp() {
        return Utils.timestampSeconds(timestamp);
    }

    public void setSigner(OauthProxyTokenSigner signer) {
        this.signer = signer;
    }

    public byte[] dumps(String payload) {
        try {
            return signer.sign(payload.getBytes());
        } catch (Exception e) {
            return new byte[]{};
        }
    }

    public void unsign() throws BadSignatureException {
        signer.fast_unsign(this.message.getBytes(), this.signature.getBytes());
    }

    public byte[] getSeparator() {
        return separator;
    }

    @Override
    public String serialize() {
        return String.format("%s%s%s%s%s", payload, new String(separator), timestamp, new String(separator), signature);
    }

    @Override
    public void resign() throws Exception {
        byte[] value = message.getBytes();
        this.signature = new String(signer.get_signature_unsafe(value));
    }

    @Override
    public void setClaims(JWTClaimsSet claims) {
        this.payload = new String(Base64.getUrlEncoder().encode(claims.toString().getBytes()));
        this.message = String.format("%s%s%s%s%s", parameter, new String(separator), payload, new String(separator), timestamp);
    }

    public byte[] getSignature() {
        return Base64.getUrlDecoder().decode(signature);
    }

}
