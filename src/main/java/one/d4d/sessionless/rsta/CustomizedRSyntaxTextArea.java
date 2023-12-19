package one.d4d.sessionless.rsta;

import one.d4d.sessionless.utils.FontProvider;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.Theme;

import java.awt.*;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.util.function.Consumer;

import static one.d4d.sessionless.rsta.CustomTokenColors.customTokenColors;
import static java.awt.event.HierarchyEvent.SHOWING_CHANGED;
import static org.fife.ui.rsyntaxtextarea.Theme.load;

class CustomizedRSyntaxTextArea extends RSyntaxTextArea {
    private static final String DARK_THEME = "/org/fife/ui/rsyntaxtextarea/themes/dark.xml";
    private static final String LIGHT_THEME = "/org/fife/ui/rsyntaxtextarea/themes/default.xml";
    private static final double LINE_HEIGHT_SCALING_FACTOR = 1.15;

    private final DarkModeDetector darkModeDetector;
    private final FontProvider fontProvider;
    private final Consumer<String> errorLogger;
    private final CustomTokenColors customTokenColors;

    CustomizedRSyntaxTextArea(
            DarkModeDetector darkModeDetector,
            FontProvider fontProvider,
            Consumer<String> errorLogger) {
        this(darkModeDetector, fontProvider, errorLogger, customTokenColors().build());
    }

    CustomizedRSyntaxTextArea(
            DarkModeDetector darkModeDetector,
            FontProvider fontProvider,
            Consumer<String> errorLogger,
            CustomTokenColors customTokenColors) {
        this.darkModeDetector = darkModeDetector;
        this.fontProvider = fontProvider;
        this.errorLogger = errorLogger;
        this.customTokenColors = customTokenColors;

        this.addHierarchyListener(e -> {
            if (e.getChangeFlags() == SHOWING_CHANGED && e.getComponent().isShowing()) {
                applyThemeAndFont();
            }
        });

        setUseFocusableTips(false);
        setBracketMatchingEnabled(false);
        setShowMatchedBracketPopup(false);
    }

    @Override
    public String getToolTipText(MouseEvent e) {
        return null;
    }

    @Override
    protected String getToolTipTextImpl(MouseEvent e) {
        return null;
    }

    @Override
    public void setSyntaxEditingStyle(String styleKey) {
        super.setSyntaxEditingStyle(styleKey);
        applyThemeAndFont();
    }

    @Override
    public void updateUI() {
        super.updateUI();
        applyThemeAndFont();
    }

    @Override
    public Color getForegroundForTokenType(int type) {
        return customTokenColors
                .foregroundForTokenType(type)
                .orElse(super.getForegroundForTokenType(type));
    }

    @Override
    public int getLineHeight() {
        return (int) (super.getLineHeight() * LINE_HEIGHT_SCALING_FACTOR);
    }

    private void applyThemeAndFont() {
        if (errorLogger == null || fontProvider == null) {
            return;
        }

        String themeResource = darkModeDetector.isDarkMode() ? DARK_THEME : LIGHT_THEME;

        try {
            Theme theme = load(getClass().getResourceAsStream(themeResource));
            theme.apply(this);

            Font font = fontProvider.editorFont();
            setFont(font);
        } catch (IOException e) {
            errorLogger.accept(e.getMessage());
        }
    }
}
