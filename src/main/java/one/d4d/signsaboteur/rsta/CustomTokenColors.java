package one.d4d.signsaboteur.rsta;

import java.awt.*;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

class CustomTokenColors {
    private final Map<Integer, Color> foregroundColors;

    private CustomTokenColors(Map<Integer, Color> foregroundColors) {
        this.foregroundColors = foregroundColors;
    }

    Optional<Color> foregroundForTokenType(int type) {
        return Optional.ofNullable(foregroundColors.get(type));
    }

    static CustomTokenColorsBuilder customTokenColors() {
        return new CustomTokenColorsBuilder();
    }

    static class CustomTokenColorsBuilder {
        private final Map<Integer, Color> foregroundColors = new HashMap<>();

        private CustomTokenColorsBuilder() {
        }

        CustomTokenColorsBuilder withForeground(int type, Color color) {
            foregroundColors.put(type, color);
            return this;
        }

        CustomTokenColors build() {
            return new CustomTokenColors(foregroundColors);
        }
    }
}
