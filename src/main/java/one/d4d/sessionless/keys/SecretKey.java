package one.d4d.sessionless.keys;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import one.d4d.sessionless.itsdangerous.Algorithms;
import one.d4d.sessionless.itsdangerous.Derivation;
import one.d4d.sessionless.itsdangerous.MessageDigestAlgorithm;

public class SecretKey implements Key {
    @Expose
    @SerializedName("keyId")
    private final String keyId;
    @Expose
    @SerializedName("secret")
    private final String secret;
    @Expose
    @SerializedName("salt")
    private final String salt;
    @Expose
    @SerializedName("separator")
    private final String separator;
    @Expose
    @SerializedName("digestMethod")
    private final Algorithms digestMethod;
    @Expose
    @SerializedName("keyDerivation")
    private final Derivation keyDerivation;
    @Expose
    @SerializedName("messageDigestAlgorythm")
    private final MessageDigestAlgorithm messageDigestAlgorithm;

    public SecretKey(
            String keyId,
            String secret,
            String salt,
            String separator,
            Algorithms digestMethod,
            Derivation keyDerivation,
            MessageDigestAlgorithm messageDigestAlgorithm) {
        this.keyId = keyId;
        this.secret = secret;
        this.salt = salt;
        this.separator = separator;
        this.digestMethod = digestMethod;
        this.keyDerivation = keyDerivation;
        this.messageDigestAlgorithm = messageDigestAlgorithm;
    }

    public String getSecret() {
        return secret;
    }

    public String getSalt() {
        return salt;
    }

    public String getSeparator() {
        return separator;
    }

    public Algorithms getDigestMethod() {
        return digestMethod;
    }

    public Derivation getKeyDerivation() {
        return keyDerivation;
    }

    public MessageDigestAlgorithm getMessageDigestAlgorythm() {
        return messageDigestAlgorithm;
    }

    @Override
    public String getID() {
        return keyId;
    }

    @Override
    public String toString() {
        return keyId;
    }

    public String toJSONString() {
        return "{" +
                "keyId='" + keyId + '\'' +
                ", secret='" + secret + '\'' +
                ", salt='" + salt + '\'' +
                ", separator='" + separator + '\'' +
                ", digestMethod=" + digestMethod +
                ", keyDerivation=" + keyDerivation +
                ", messageDigestAlgorythm=" + messageDigestAlgorithm +
                '}';
    }
}
