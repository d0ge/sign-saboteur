package burp.config;

import burp.api.montoya.persistence.Preferences;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import one.d4d.signsaboteur.itsdangerous.BruteForce;
import one.d4d.signsaboteur.presenter.PresenterStore;

public class BurpConfigPersistence {
    static final String BURP_SETTINGS_NAME = "one.d4d.signsaboteur.settings";
    private final Preferences preferences;
    private final PresenterStore presenters;

    public BurpConfigPersistence(Preferences preferences, PresenterStore presenters) {
        this.preferences = preferences;
        this.presenters = presenters;
    }

    public BurpConfig loadOrCreateNew() {
        String json = preferences.getString(BURP_SETTINGS_NAME);

        if (json == null) {
            return new BurpConfig();
        }

        Gson gson = new Gson();
        return gson.fromJson(json, BurpConfig.class);
    }

    public void unload(BurpConfig model) {
        Gson gson = new GsonBuilder()
                .excludeFieldsWithoutExposeAnnotation()
                .create();
        String burpConfigJson = gson.toJson(model);

        preferences.setString(BURP_SETTINGS_NAME, burpConfigJson);
        try {
            BruteForce presenter = (BruteForce) presenters.get(BruteForce.class);
            presenter.shutdown();
        } catch (Exception ignored){}
    }
}
