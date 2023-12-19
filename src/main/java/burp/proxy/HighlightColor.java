package burp.proxy;

import java.awt.*;

import static java.util.Arrays.stream;

public enum HighlightColor {
    RED("Red", burp.api.montoya.core.HighlightColor.RED, Color.RED),
    ORANGE("Orange", burp.api.montoya.core.HighlightColor.ORANGE, Color.ORANGE),
    YELLOW("Yellow", burp.api.montoya.core.HighlightColor.YELLOW, Color.YELLOW),
    GREEN("Green", burp.api.montoya.core.HighlightColor.GREEN, Color.GREEN),
    CYAN("Cyan", burp.api.montoya.core.HighlightColor.CYAN, Color.CYAN),
    BLUE("Blue", burp.api.montoya.core.HighlightColor.BLUE, Color.BLUE),
    PINK("Pink", burp.api.montoya.core.HighlightColor.PINK, Color.PINK),
    MAGENTA("Magenta", burp.api.montoya.core.HighlightColor.MAGENTA, Color.MAGENTA),
    GRAY("Gray", burp.api.montoya.core.HighlightColor.GRAY, Color.GRAY);

    public final burp.api.montoya.core.HighlightColor burpColor;
    public final Color color;

    private final String displayName;

    HighlightColor(String displayName, burp.api.montoya.core.HighlightColor burpColor, Color color) {
        this.displayName = displayName;
        this.burpColor = burpColor;
        this.color = color;
    }

    public static HighlightColor from(String displayName) {
        return stream(values()).filter(highlightColor -> highlightColor.displayName.equalsIgnoreCase(displayName)).findFirst().orElse(null);
    }

    @Override
    public String toString() {
        return displayName;
    }
}
