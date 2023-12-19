package one.d4d.sessionless.itsdangerous;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public enum Algorithms {
    @Expose @SerializedName("1") SHA1("HmacSHA1"),
    @Expose @SerializedName("2") SHA224("HmacSHA224"),
    @Expose @SerializedName("3") SHA256("HmacSHA256"),
    @Expose @SerializedName("4") SHA384("HmacSHA384"),
    @Expose @SerializedName("5") SHA512("HmacSHA512");
    public final String name;

    Algorithms(String name) {
        this.name = name;
    }
}
