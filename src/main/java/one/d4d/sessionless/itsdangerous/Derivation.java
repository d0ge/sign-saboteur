package one.d4d.sessionless.itsdangerous;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public enum Derivation {
    @Expose @SerializedName("1") PBKDF2HMAC("PBKDF2HMAC"),
    @Expose @SerializedName("2") HASH("hash"),
    @Expose @SerializedName("3") CONCAT("concat"),
    @Expose @SerializedName("4") DJANGO("django-concat"),
    @Expose @SerializedName("5") HMAC("hmac"),
    @Expose @SerializedName("6") NONE("none");
    public final String name;

    Derivation(String name) {
        this.name = name;
    }

}
