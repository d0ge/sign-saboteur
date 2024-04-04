package one.d4d.signsaboteur.forms;

import one.d4d.signsaboteur.keys.SecretKey;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

class KeysTableModel extends AbstractTableModel {
    private final List<SecretKey> data;

    KeysTableModel(Iterable<SecretKey> keys) {
        this.data = new ArrayList<>();
        keys.forEach(data::add);
    }

    void addKey(SecretKey key) {
        int nextRowIndex = data.size();
        data.add(key);
        fireTableRowsInserted(nextRowIndex, nextRowIndex);
    }

    void deleteRow(int rowIndex) {
        data.remove(rowIndex);
        fireTableRowsDeleted(rowIndex, rowIndex);
    }

    @Override
    public int getRowCount() {
        return data.size();
    }

    @Override
    public int getColumnCount() {
        return KeysTableColumns.values().length;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        if (rowIndex < 0 || rowIndex >= data.size()) {
            return null;
        }

        SecretKey key = data.get(rowIndex);
        KeysTableColumns column = KeysTableColumns.fromIndex(columnIndex);

        return switch (column) {
            case ID -> key.getID();
            case SECRET -> key.getSecret();
            case ALGORITHM -> key.getDigestMethod();
            case DERIVATION -> key.getKeyDerivation();
            case MESSAGE_DERIVATION -> key.getMessageDerivation();
            case DIGEST -> key.getMessageDigestAlgorythm();
        };
    }

    @Override
    public String getColumnName(int column) {
        return KeysTableColumns.labelWithIndex(column);
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return KeysTableColumns.typeForIndex(columnIndex);
    }
}
