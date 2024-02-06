package one.d4d.sessionless.itsdangerous.model;

import com.nimbusds.jwt.JWTClaimsSet;
import one.d4d.sessionless.itsdangerous.crypto.JSONWebSignatureTokenSigner;

import java.util.Base64;

public class JSONWebSignature extends SignedToken {
    public String header;
    public String payload;
    public byte[] separator;

    public JSONWebSignature(String header, String payload, String signature, byte[] separator) {
        super(String.format("%s%s%s", header, new String(separator), payload));
        this.header = header;
        this.payload = payload;
        this.signature = signature;
        this.separator = separator;
        this.signer = new JSONWebSignatureTokenSigner(separator);
    }

    public String getHeader() {
        try {
            return new String(Base64.getUrlDecoder().decode(header));
        } catch (IllegalArgumentException e) {
            return "";
        }
    }

    public void setHeader(String header) {
        this.header = header;
    }

    public String getPayload() {
        try {
            return new String(Base64.getUrlDecoder().decode(payload));
        } catch (IllegalArgumentException e) {
            return "";
        }
    }

    public void setPayload(String payload) {
        this.payload = payload;
    }

    public byte[] getSeparator() {
        return separator;
    }

    public void setSeparator(byte[] separator) {
        this.separator = separator;
    }

    @Override
    public String serialize() {
        return String.format("%s%s%s%s%s", header, new String(separator), payload, new String(separator), signature);
    }


    public void resign() throws Exception {
        this.signature = new String(signer.get_signature_unsafe(message.getBytes()));
    }

    @Override
    public void setClaims(JWTClaimsSet claims) {
        this.payload = new String(Base64.getUrlEncoder().withoutPadding().encode(claims.toString().getBytes()));
        this.message = String.format("%s%s%s", header, new String(separator), payload);
    }

    @Override
    public byte[] getSignature() {
        try {
            return Base64.getUrlDecoder().decode(signature);
        } catch (IllegalArgumentException e) {
            return new byte[]{};
        }
    }
}
