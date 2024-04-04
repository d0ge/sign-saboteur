package one.d4d.signsaboteur.utils;

import burp.api.montoya.ui.UserInterface;

import java.awt.*;

public class FontProvider {
    private final UserInterface userInterface;

    public FontProvider(UserInterface userInterface) {
        this.userInterface = userInterface;
    }

    public Font editorFont() {
        return userInterface.currentEditorFont();
    }
}
