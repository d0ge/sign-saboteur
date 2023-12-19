package one.d4d.sessionless.itsdangerous.model;

import one.d4d.sessionless.itsdangerous.Algorithms;
import one.d4d.sessionless.itsdangerous.Derivation;
import one.d4d.sessionless.itsdangerous.MessageDigestAlgorithm;
import one.d4d.sessionless.utils.Utils;

public class DjangoSignedToken extends DangerousSignedToken {

    public DjangoSignedToken(byte separator, String payload, String timestamp, String signature) {
        super(separator, payload, timestamp, signature, Algorithms.SHA1, Derivation.DJANGO, MessageDigestAlgorithm.SHA1);
    }

    @Override
    public String toString() {
        try {
            StringBuilder sb = new StringBuilder();
            byte[] json = Utils.base64Decompress(this.payload.getBytes());
            sb.append(new String(json)).append(this.separator);
            sb.append(Utils.base62timestamp(this.timestamp.getBytes())).append(this.separator);
            sb.append(this.signature);
            return sb.toString();
        } catch (Exception e) {
            return String.format("%s%c%s%c%s", payload, (char) separator, timestamp, (char) separator, signature);
        }
    }

    @Override
    public String getTimestamp() {
        try {
            return Utils.base62timestamp(timestamp.getBytes());
        } catch (Exception e) {
            return Utils.timestamp(timestamp.getBytes());
        }
    }
}
