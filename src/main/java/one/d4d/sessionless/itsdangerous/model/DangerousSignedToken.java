package one.d4d.sessionless.itsdangerous.model;

import com.nimbusds.jwt.JWTClaimsSet;
import one.d4d.sessionless.itsdangerous.*;
import one.d4d.sessionless.itsdangerous.crypto.DangerousTokenSigner;
import one.d4d.sessionless.utils.Utils;

import java.util.Base64;

public class DangerousSignedToken extends SignedToken {
    public final String timestamp;
    public String payload;
    public byte separator;

    public DangerousSignedToken(byte separator, String payload, String timestamp, String signature) {
        super(String.format("%s%c%s", payload, separator, timestamp));
        this.separator = separator;
        this.payload = payload;
        this.timestamp = timestamp;
        this.signature = signature;
        this.signer = new DangerousTokenSigner(separator);
    }

    public DangerousSignedToken(
            byte separator,
            String payload,
            String timestamp,
            String signature,
            Algorithms algorithm,
            Derivation derivation,
            MessageDerivation messageDerivation,
            MessageDigestAlgorithm digest) {
        super(String.format("%s%c%s", payload, separator, timestamp));
        this.separator = separator;
        this.payload = payload;
        this.timestamp = timestamp;
        this.signature = signature;
        this.signer = new DangerousTokenSigner(
                algorithm,
                derivation,
                messageDerivation,
                digest,
                new byte[]{},
                new byte[]{},
                separator
        );
    }

    public void setSigner(DangerousTokenSigner signer) {
        this.signer = signer;
    }

    public String dumps() {
        byte[] header = Base64.getUrlEncoder().withoutPadding().encode(payload.getBytes());
        String message = String.format("%s%c%s", new String(header), (char) this.separator, this.timestamp);
        return new String(signer.sign(message.getBytes()));
    }

    public void resign() throws Exception {
        this.signature = new String(signer.get_signature_unsafe(message.getBytes()));
    }

    @Override
    public void setClaims(JWTClaimsSet claims) {
        if (isCompressed()) {
            this.payload = Utils.compressBase64(claims.toString().getBytes());
        } else {
            this.payload = new String(Base64.getUrlEncoder().withoutPadding().encode(claims.toString().getBytes()));
        }
        this.message = String.format("%s%c%s", payload, separator, timestamp);
    }


    public String toString() {
        try {
            StringBuilder sb = new StringBuilder();
            byte[] json = Utils.base64Decompress(this.payload.getBytes());
            sb.append(new String(json)).append(this.separator);
            sb.append(Utils.base64timestamp(this.timestamp.getBytes())).append(this.separator);
            sb.append(this.signature);
            return sb.toString();
        } catch (Exception e) {
            return String.format("%s%c%s%c%s", payload, (char) separator, timestamp, (char) separator, signature);
        }
    }

    public String serialize() {
        return String.format("%s%c%s%c%s", payload, (char) separator, timestamp, (char) separator, signature);
    }


    public String getPayload() {
        return payload;
    }

    public boolean isCompressed() {
        return payload.startsWith(".");
    }

    public String getTimestamp() {
        try {
            return Utils.base64timestamp(timestamp.getBytes());
        } catch (Exception e) {
            return Utils.timestamp(timestamp.getBytes());
        }
    }

    public byte[] getSignature() {
        return Base64.getUrlDecoder().decode(signature);
    }

    public byte[] getSeparator() {
        return new byte[]{separator};
    }
}