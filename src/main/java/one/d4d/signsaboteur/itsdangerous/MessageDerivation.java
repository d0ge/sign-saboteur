package one.d4d.signsaboteur.itsdangerous;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public enum MessageDerivation {
    @Expose @SerializedName("0") NONE("none"),
    @Expose @SerializedName("1") CONCAT("concat"),
    @Expose @SerializedName("2") TORNADO("tornado");
    public final String name;
    MessageDerivation(String name) {
        this.name = name;
    }
}
