package one.d4d.signsaboteur.itsdangerous;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public enum Derivation {
    @Expose @SerializedName("1") PBKDF2HMAC("PBKDF2HMAC"),
    @Expose @SerializedName("2") HASH("hash"),
    @Expose @SerializedName("3") CONCAT("concat"),
    @Expose @SerializedName("4") DJANGO("django-concat"),
    @Expose @SerializedName("5") HMAC("hmac"),
    @Expose @SerializedName("6") NONE("none"),
    @Expose @SerializedName("7") RUBY("RUBY"),
    @Expose @SerializedName("8") RUBY5("RUBY5"),
    @Expose @SerializedName("9") RUBY5_TRUNCATED("RUBY5_TRUNCATED");
    public final String name;

    Derivation(String name) {
        this.name = name;
    }

}
