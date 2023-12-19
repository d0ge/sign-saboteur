package one.d4d.sessionless.forms;

import burp.api.montoya.ui.UserInterface;
import burp.config.BurpConfig;
import burp.config.BurpKeysModelPersistence;
import burp.config.KeysModel;
import one.d4d.sessionless.presenter.PresenterStore;
import one.d4d.sessionless.utils.Utils;

import javax.swing.*;
import java.awt.*;

public class ExtensionTab {
    private final Window parent;
    private final PresenterStore presenters;
    private final UserInterface userInterface;
    private final BurpConfig burpConfig;
    private final KeysModel keysModel;
    private final BurpKeysModelPersistence keysModelPersistence;
    private JPanel rootPanel;
    private WordlistView wordlistView;
    private SettingsView settingsView;

    public ExtensionTab(
            Window parent,
            PresenterStore presenters,
            KeysModel keysModel,
            BurpKeysModelPersistence keysModelPersistence,
            BurpConfig burpConfig,
            UserInterface userInterface) {
        this.parent = parent;
        this.keysModel = keysModel;
        this.keysModelPersistence = keysModelPersistence;
        this.burpConfig = burpConfig;
        this.userInterface = userInterface;
        this.presenters = presenters;
    }

    public String getTabCaption() {
        return Utils.getResourceString("tool_name");
    }

    public Component getUiComponent() {
        return rootPanel;
    }

    private void createUIComponents() {
        wordlistView = new WordlistView(parent, keysModel, presenters, keysModelPersistence, userInterface);
        settingsView = new SettingsView(parent, burpConfig, userInterface);
    }
}
