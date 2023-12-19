package one.d4d.sessionless.itsdangerous;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public enum MessageDigestAlgorithm {
    @Expose @SerializedName("1") MD5("MD5"),
    @Expose @SerializedName("2") SHA1("SHA-1"),
    @Expose @SerializedName("3") SHA224("SHA-224"),
    @Expose @SerializedName("4") SHA256("SHA-256"),
    @Expose @SerializedName("5") SHA384("SHA-384"),
    @Expose @SerializedName("6") SHA512("SHA-512"),
    @Expose @SerializedName("7") NONE("NONE");

    public final String name;

    MessageDigestAlgorithm(String name) {
        this.name = name;
    }

}
