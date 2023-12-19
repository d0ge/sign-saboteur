package one.d4d.sessionless.forms;

import burp.api.montoya.ui.UserInterface;
import burp.config.BurpKeysModelPersistence;
import burp.config.KeysModel;
import one.d4d.sessionless.PercentageBasedColumnWidthTable;
import one.d4d.sessionless.RowHeightDecoratingTableCellRenderer;
import one.d4d.sessionless.keys.SecretKey;
import one.d4d.sessionless.presenter.KeyPresenter;
import one.d4d.sessionless.presenter.PresenterStore;
import one.d4d.sessionless.utils.Utils;

import javax.swing.*;
import javax.swing.table.TableCellRenderer;
import java.awt.*;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

public class WordlistView {
    private final Window parent;
    private final KeysModel keysModel;
    private final BurpKeysModelPersistence keysModelPersistence;
    private final UserInterface userInterface;
    private final KeysTableModel keysTableModel;
    private final DefaultListModel<String> modelSecrets = new DefaultListModel<>();
    private final DefaultListModel<String> modelSalts = new DefaultListModel<>();
    private JPanel mainPanel;
    private JButton secretsLoadButton;
    private JButton secretsRemoveButton;
    private JButton secretsCleanButton;
    private JButton saltsRemoveButton;
    private JButton saltsCleanButton;
    private JList secretsList;
    private JList saltsList;
    private JButton saltsLoadButton;
    private JButton newKeyButton;
    private JTable tableKeys;
    private JTextArea textAreaSalts;
    private JTextArea textAreaSecrets;
    private final KeyPresenter presenter;
    private JMenuItem menuItemDelete;
    private JMenuItem menuItemCopy;


    public WordlistView(
            Window parent,
            KeysModel keysModel,
            PresenterStore presenters,
            BurpKeysModelPersistence keysModelPersistence,
            UserInterface userInterface) {
        this.parent = parent;
        this.keysModel = keysModel;
        this.keysModelPersistence = keysModelPersistence;
        this.userInterface = userInterface;

        keysTableModel = new KeysTableModel(keysModel.getSigningKeys());
        tableKeys.setModel(keysTableModel);

        modelSecrets.addAll(keysModel.getSecrets());
        modelSalts.addAll(keysModel.getSalts());

        secretsList.setModel(modelSecrets);
        secretsList.setSelectedIndex(0);
        secretsList.setFixedCellWidth(256);

        saltsList.setModel(modelSalts);
        saltsList.setSelectedIndex(0);
        saltsList.setFixedCellWidth(256);
        textAreaSecrets.setText(keysModel.getSecretsFilePath());
        textAreaSalts.setText(keysModel.getSaltsFilePath());

        presenter = new KeyPresenter(
                this,
                presenters,
                keysModel,
                keysModelPersistence,
                modelSecrets,
                modelSalts);

        secretsLoadButton.addActionListener(presenter::onButtonLoadSecretsClick);
        secretsRemoveButton.addActionListener(presenter::onButtonRemoveSecretsClick);
        secretsCleanButton.addActionListener(presenter::onButtonCleanSecretsClick);

        saltsLoadButton.addActionListener(presenter::onButtonLoadSaltsClick);
        saltsRemoveButton.addActionListener(presenter::onButtonRemoveSaltsClick);
        saltsCleanButton.addActionListener(presenter::onButtonCleanSaltsClick);

        userInterface.applyThemeToComponent(mainPanel);

        // Attach event handlers for button clicks
        newKeyButton.addActionListener(e -> presenter.onButtonNewSecretKeyClick());
    }
    /**
     * Class for the right-click popup menu
     */
    private class JTablePopup extends PercentageBasedColumnWidthTable {
        private Integer popupRow;

        public JTablePopup() {
            super(KeysTableColumns.columnWidthPercentages());
        }

        @Override
        public JPopupMenu getComponentPopupMenu() {
            // Get the row that has been right-clicked on
            Point p = getMousePosition();

            if (p == null || rowAtPoint(p) < 0) {
                popupRow = null;
                return null;
            }

            popupRow = rowAtPoint(p);

            boolean copyEnabled = false;

            // No selection, set the selection
            if (tableKeys.getSelectedRowCount() == 0) {
                tableKeys.changeSelection(popupRow, 0, false, false);
            }
            // Selection equals right-clicked row - this will trigger on right-click release
            else if (tableKeys.getSelectedRowCount() == 1 && tableKeys.getSelectedRow() == popupRow) {
                copyEnabled = keysModel.getKey(popupRow) != null;
            }
            // Selection doesn't equal right-clicked row, change the selection
            else if (tableKeys.getSelectedRowCount() == 1 && tableKeys.getSelectedRow() != popupRow) {
                tableKeys.changeSelection(popupRow, 0, false, false);
            }

            menuItemCopy.setEnabled(copyEnabled);

            return super.getComponentPopupMenu();
        }

        public Integer getPopupRow() {
            return popupRow;
        }
    }

    public Component getUiComponent() {
        return mainPanel;
    }

    public JList getSecretsList() {
        return secretsList;
    }

    public JList getSaltsList() {
        return saltsList;
    }

    public JTextArea getSecretsTextArea() {
        return textAreaSecrets;
    }

    public JTextArea getSaltsTextArea() {
        return textAreaSalts;
    }

    public int getSelectedRow() {
        return tableKeys.getSelectedRow();
    }

    private void createUIComponents() {
        tableKeys = new JTablePopup();

        // Add a handler for double-click events
        tableKeys.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent mouseEvent) {
                // Detect double-clicks and pass the event to the presenter
                if (mouseEvent.getButton() == 1 && mouseEvent.getClickCount() == 2) {
                    presenter.onTableKeysDoubleClick();
                }
            }
        });

        // Decorate existing renderer to add additional row height
        TableCellRenderer stringCellRender = tableKeys.getDefaultRenderer(String.class);
        tableKeys.setDefaultRenderer(String.class, new RowHeightDecoratingTableCellRenderer(stringCellRender));

        // Create the right-click menu
        JPopupMenu popupMenu = new JPopupMenu();

        menuItemDelete = new JMenuItem(Utils.getResourceString("table_menu_delete"));
        menuItemCopy = new JMenuItem(Utils.getResourceString("table_menu_copy"));

        // Event handlers that call the presenter for menu item clicks on the right-click menu
        ActionListener popupMenuActionListener = e -> {
            JMenuItem menuItem = (JMenuItem) e.getSource();
            if (menuItem == menuItemDelete) {
                presenter.onPopupDelete(tableKeys.getSelectedRows());
            } else if (menuItem == menuItemCopy) {
                presenter.onPopupCopy(((JTablePopup) tableKeys).getPopupRow());
            }
        };

        // Attach the event handler to the right-click menu buttons
        menuItemDelete.addActionListener(popupMenuActionListener);
        menuItemCopy.addActionListener(popupMenuActionListener);

        // Add the buttons to the right-click menu
        popupMenu.add(menuItemDelete);
        popupMenu.add(menuItemCopy);

        // Associate the right-click menu to the table
        tableKeys.setComponentPopupMenu(popupMenu);
    }

    public void addKey(SecretKey key) {
        keysTableModel.addKey(key);
    }

    public void deleteKey(int rowIndex) {
        keysTableModel.deleteRow(rowIndex);
    }

    public Window getParent() {
        return parent;
    }

}
