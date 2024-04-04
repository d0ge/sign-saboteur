package one.d4d.signsaboteur.rsta;

import burp.api.montoya.ui.Theme;
import burp.api.montoya.ui.UserInterface;

class DarkModeDetector {
    private final UserInterface userInterface;

    DarkModeDetector(UserInterface userInterface) {
        this.userInterface = userInterface;
    }

    boolean isDarkMode() {
        return userInterface.currentTheme() == Theme.DARK;
    }
}
