package one.d4d.signsaboteur.utils;

import javax.swing.*;
import java.util.List;

public class MaxLengthStringComboBoxModel extends DefaultComboBoxModel<String> {
    private static final String FORMAT_STRING = "%s ...";

    public MaxLengthStringComboBoxModel(int maxLength, List<String> items) {
        super(items.stream().map(item -> truncateIfRequired(maxLength, item)).toArray(String[]::new));
    }

    private static String truncateIfRequired(int maxLength, String item) {
        return item != null && item.length() > maxLength
                ? FORMAT_STRING.formatted(item.substring(0, maxLength))
                : item;
    }
}
