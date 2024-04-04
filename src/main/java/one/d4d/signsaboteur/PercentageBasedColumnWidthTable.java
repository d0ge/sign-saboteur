package one.d4d.signsaboteur;

import javax.swing.*;
import javax.swing.table.TableColumnModel;
import java.awt.event.HierarchyEvent;
import java.awt.event.HierarchyListener;

import static java.awt.event.HierarchyEvent.SHOWING_CHANGED;

public class PercentageBasedColumnWidthTable extends JTable {
    private final int[] columnWidthPercentages;

    public PercentageBasedColumnWidthTable(int[] columnWidthPercentages) {
        this.columnWidthPercentages = columnWidthPercentages;
        addHierarchyListener(new ResizeColumnsOnFirstRenderHierarchyListener());

        tableHeader.setReorderingAllowed(false);
    }

    private void resizeColumns() {
        TableColumnModel columnModel = this.getColumnModel();

        if (columnWidthPercentages == null || columnModel.getColumnCount() != columnWidthPercentages.length) {
            return;
        }

        int tableWidth = getWidth();

        for (int i = 0; i < columnWidthPercentages.length; i++) {
            int preferredWidth = (int) (columnWidthPercentages[i] * 0.01 * tableWidth);
            columnModel.getColumn(i).setPreferredWidth(preferredWidth);
        }
    }

    private class ResizeColumnsOnFirstRenderHierarchyListener implements HierarchyListener {
        @Override
        public void hierarchyChanged(HierarchyEvent e) {
            if (e.getChangeFlags() != SHOWING_CHANGED || !e.getComponent().isShowing()) {
                return;
            }

            resizeColumns();
            removeHierarchyListener(this);
        }
    }
}
