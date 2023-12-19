package one.d4d.sessionless.rsta;

import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.UserInterface;
import one.d4d.sessionless.rsta.token.SignedTokenMaker;
import one.d4d.sessionless.rsta.token.SignedTokenizerConstants;
import one.d4d.sessionless.utils.FontProvider;
import org.fife.ui.rsyntaxtextarea.AbstractTokenMakerFactory;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.TokenMakerFactory;

import javax.swing.*;
import javax.swing.text.JTextComponent;
import java.awt.*;
import java.util.function.Supplier;

import static one.d4d.sessionless.rsta.CustomTokenColors.customTokenColors;
import static one.d4d.sessionless.rsta.token.SignedTokenMaker.*;
import static one.d4d.sessionless.rsta.token.SignedTokenizerConstants.MAPPING;
import static one.d4d.sessionless.rsta.token.SignedTokenizerConstants.TOKEN_MAKER_FQCN;

public class RstaFactory {
    private final DarkModeDetector darkModeDetector;
    private final FontProvider fontProvider;
    private final Logging logging;

    public RstaFactory(UserInterface userInterface, Logging logging) {
        this.darkModeDetector = new DarkModeDetector(userInterface);
        this.fontProvider = new FontProvider(userInterface);
        this.logging = logging;

        AbstractTokenMakerFactory tokenMakerFactory = (AbstractTokenMakerFactory) TokenMakerFactory.getDefaultInstance();
        tokenMakerFactory.putMapping(MAPPING, TOKEN_MAKER_FQCN);
        SignedTokenMaker.errorLogger = logging::logToError;
    }

    public RSyntaxTextArea buildDefaultTextArea() {
        return fixKeyEventCapture(
                () -> new CustomizedRSyntaxTextArea(darkModeDetector, fontProvider, logging::logToError)
        );
    }

    public RSyntaxTextArea buildSerializedJWTTextArea() {
        CustomTokenColors customTokenColors = customTokenColors()
                .withForeground(JWT_PART1, Color.decode("#FB015B"))
                .withForeground(JWT_PART2, Color.decode("#D63AFF"))
                .withForeground(JWT_PART3, Color.decode("#00B9F1"))
                .withForeground(JWT_PART4, Color.decode("#EA7600"))
                .withForeground(JWT_PART5, Color.decode("#EDB219"))
                .withForeground(JWT_SEPARATOR1, Color.decode("#A6A282"))
                .withForeground(JWT_SEPARATOR2, Color.decode("#A6A282"))
                .withForeground(JWT_SEPARATOR3, Color.decode("#A6A282"))
                .withForeground(JWT_SEPARATOR4, Color.decode("#A6A282"))
                .build();

        RSyntaxTextArea textArea = fixKeyEventCapture(
                () -> new CustomizedRSyntaxTextArea(
                        darkModeDetector,
                        fontProvider,
                        logging::logToError,
                        customTokenColors
                )
        );

        textArea.setSyntaxEditingStyle(SignedTokenizerConstants.MAPPING);

        return textArea;
    }

    // Ensure Burp key events not captured - https://github.com/bobbylight/RSyntaxTextArea/issues/269#issuecomment-776329702
    private RSyntaxTextArea fixKeyEventCapture(Supplier<RSyntaxTextArea> rSyntaxTextAreaSupplier) {
        JTextComponent.removeKeymap("RTextAreaKeymap");

        RSyntaxTextArea textArea = rSyntaxTextAreaSupplier.get();

        UIManager.put("RSyntaxTextAreaUI.actionMap", null);
        UIManager.put("RSyntaxTextAreaUI.inputMap", null);
        UIManager.put("RTextAreaUI.actionMap", null);
        UIManager.put("RTextAreaUI.inputMap", null);

        return textArea;
    }
}
