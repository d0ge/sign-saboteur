package one.d4d.signsaboteur.forms.dialog;

import one.d4d.signsaboteur.utils.Utils;

import javax.swing.*;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

import static java.awt.Dialog.ModalityType.APPLICATION_MODAL;

public abstract class AbstractDialog extends JDialog {

    protected AbstractDialog(Window parent, String titleResourceId) {
        super(parent, Utils.getResourceString(titleResourceId), APPLICATION_MODAL);

        setDefaultCloseOperation(DO_NOTHING_ON_CLOSE);

        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                onCancel();
            }
        });
    }

    public void display() {
        pack();
        setLocationRelativeTo(getOwner());
        setVisible(true);
    }

    protected void onCancel() {
        dispose();
    }
}
