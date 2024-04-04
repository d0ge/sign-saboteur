package one.d4d.signsaboteur.forms;

import one.d4d.signsaboteur.utils.Utils;

import javax.swing.*;
import java.awt.*;

import static javax.swing.JOptionPane.ERROR_MESSAGE;
import static javax.swing.JOptionPane.WARNING_MESSAGE;

public class MessageDialogFactory {
    private final Component parent;

    public MessageDialogFactory(Component parent) {
        this.parent = parent;
    }
    public void showErrorDialog(String titleKey, String messageKey, Object... args) {
        showDialog(ERROR_MESSAGE, titleKey, messageKey, args);
    }

    public void showWarningDialog(String titleKey, String messageKey, Object... args) {
        showDialog(WARNING_MESSAGE, titleKey, messageKey, args);
    }

    private void showDialog(int messageType, String titleKey, String messageKey, Object... args) {
        JOptionPane.showMessageDialog(
                parent,
                Utils.getResourceString(messageKey).formatted(args),
                Utils.getResourceString(titleKey),
                messageType
        );
    }
}
