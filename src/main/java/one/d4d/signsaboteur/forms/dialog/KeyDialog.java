package one.d4d.signsaboteur.forms.dialog;

import one.d4d.signsaboteur.keys.Key;
import one.d4d.signsaboteur.presenter.KeyPresenter;
import one.d4d.signsaboteur.presenter.PresenterStore;
import one.d4d.signsaboteur.utils.Utils;

import javax.swing.*;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

import static javax.swing.JOptionPane.*;

public abstract class KeyDialog extends JDialog {

    protected PresenterStore presenters;
    protected String originalId;

    public KeyDialog(Window parent, String titleResourceId) {
        super(parent);

        setModal(true);
        setTitle(Utils.getResourceString(titleResourceId));

        // call onCancel() when cross is clicked
        setDefaultCloseOperation(DO_NOTHING_ON_CLOSE);
        addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent e) {
                onCancel();
            }
        });
    }

    public abstract Key getKey();

    abstract void onCancel();

    public void display() {
        pack();
        setLocationRelativeTo(getOwner());
        setVisible(true);
    }

    void onOK() {
        KeyPresenter keyPresenter = (KeyPresenter) presenters.get(KeyPresenter.class);
        Key newKey = getKey();

        // Handle overwrites if a key already exists with the same kid
        if (keyPresenter.keyExists(newKey.getID())) {
            // If the new and original key ids match, then this is an update
            if (originalId != null && !originalId.equals(newKey.getID())) {
                // Otherwise, saving the key could overwrite an existing kid, so show a dialog to confirm
                if (showConfirmDialog(
                        this,
                        Utils.getResourceString("keys_confirm_overwrite"),
                        Utils.getResourceString("keys_confirm_overwrite_title"),
                        OK_CANCEL_OPTION) != OK_OPTION) {
                    return;
                }
            }
        }

        dispose();
    }
}
