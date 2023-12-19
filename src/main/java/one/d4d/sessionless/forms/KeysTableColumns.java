package one.d4d.sessionless.forms;

import one.d4d.sessionless.utils.Utils;

import static java.util.Arrays.stream;

enum KeysTableColumns {
    ID("table_id", 30, String.class),
    SECRET("table_secret", 40, String.class),
    ALGORITHM("table_algorithm", 10, String.class),
    DERIVATION("table_derivation",10, String.class),
    DIGEST("table_digest",10, String.class);

    private final String label;
    private final int widthPercentage;
    private final Class<?> type;

    KeysTableColumns(String labelResourceId, int widthPercentage, Class<?> type) {
        this.label = Utils.getResourceString(labelResourceId);
        this.widthPercentage = widthPercentage;
        this.type = type;
    }

    static int[] columnWidthPercentages() {
        return stream(values()).mapToInt(c -> c.widthPercentage).toArray();
    }

    static KeysTableColumns fromIndex(int index) {
        return values()[index];
    }

    static String labelWithIndex(int index) {
        return values()[index].label;
    }

    static Class<?> typeForIndex(int index) {
        return values()[index].type;
    }
}
