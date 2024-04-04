package one.d4d.signsaboteur.forms.dialog;

import one.d4d.signsaboteur.utils.GsonHelper;

import javax.swing.*;
import java.awt.*;
import java.awt.event.KeyEvent;

public class NewWordDialog extends AbstractDialog {
    private JPanel contentPane;
    private JButton buttonOK;
    private JButton buttonCancel;
    private JTextField textFieldItem;
    private JCheckBox checkBoxJSON;
    private String item;

    public NewWordDialog(Window parent) {
        super(parent, "new_word_dialog_title");
        setContentPane(contentPane);
        getRootPane().setDefaultButton(buttonOK);

        buttonOK.addActionListener(e -> onOK());
        buttonCancel.addActionListener(e -> onCancel());

        contentPane.registerKeyboardAction(
                e -> onCancel(),
                KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
                JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT
        );
        textFieldItem.setText("\"\"");
        checkBoxJSON.setSelected(true);
    }

    private void onOK() {
        item = checkBoxJSON.isSelected() ? GsonHelper.customGson.fromJson(textFieldItem.getText(), String.class) : textFieldItem.getText();
        dispose();
    }

    public String getItem() {
        return item;
    }
}
