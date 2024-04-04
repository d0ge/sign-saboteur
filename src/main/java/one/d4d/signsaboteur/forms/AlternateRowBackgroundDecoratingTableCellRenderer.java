package one.d4d.signsaboteur.forms;

import javax.swing.*;
import javax.swing.table.TableCellRenderer;
import java.awt.*;

public record AlternateRowBackgroundDecoratingTableCellRenderer(TableCellRenderer tableCellRenderer) implements TableCellRenderer {

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
        Component component = tableCellRenderer.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

        if (!isSelected && !hasFocus) {
            Color alternateRowColor = UIManager.getColor("Table.alternateRowColor");

            if (alternateRowColor != null && row % 2 != 0) {
                component.setBackground(alternateRowColor);
            }
        }

        return component;
    }
}
