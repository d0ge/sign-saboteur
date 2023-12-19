package one.d4d.sessionless;

import javax.swing.*;
import javax.swing.table.TableCellRenderer;
import java.awt.*;

public record RowHeightDecoratingTableCellRenderer(TableCellRenderer tableCellRenderer) implements TableCellRenderer {
    private static final int ADDITIONAL_HEIGHT_PIXELS = 5;

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
        Component component = tableCellRenderer.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
        int componentHeight = component.getPreferredSize().height;

        if (table.getRowHeight() != componentHeight + ADDITIONAL_HEIGHT_PIXELS) {
            table.setRowHeight(componentHeight + ADDITIONAL_HEIGHT_PIXELS);
        }

        return component;
    }
}
