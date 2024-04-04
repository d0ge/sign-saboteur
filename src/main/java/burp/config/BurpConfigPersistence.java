package burp.config;

import burp.api.montoya.persistence.Preferences;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class BurpConfigPersistence {
    static final String BURP_SETTINGS_NAME = "one.d4d.signsaboteur.settings";
    private final Preferences preferences;

    public BurpConfigPersistence(Preferences preferences) {
        this.preferences = preferences;
    }

    public BurpConfig loadOrCreateNew() {
        String json = preferences.getString(BURP_SETTINGS_NAME);

        if (json == null) {
            return new BurpConfig();
        }

        Gson gson = new Gson();
        return gson.fromJson(json, BurpConfig.class);
    }

    public void save(BurpConfig model) {
        Gson gson = new GsonBuilder()
                .excludeFieldsWithoutExposeAnnotation()
                .create();
        String burpConfigJson = gson.toJson(model);

        preferences.setString(BURP_SETTINGS_NAME, burpConfigJson);
    }
}
