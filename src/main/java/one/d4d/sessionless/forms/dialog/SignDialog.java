package one.d4d.sessionless.forms.dialog;

import one.d4d.sessionless.itsdangerous.crypto.*;
import one.d4d.sessionless.itsdangerous.model.*;
import one.d4d.sessionless.keys.SecretKey;
import one.d4d.sessionless.utils.ErrorLoggingActionListenerFactory;
import one.d4d.sessionless.utils.Utils;

import javax.swing.*;
import java.awt.*;
import java.awt.event.KeyEvent;
import java.util.List;

import static javax.swing.JOptionPane.WARNING_MESSAGE;

public class SignDialog extends AbstractDialog {
    private JPanel contentPane;
    private JButton buttonOK;
    private JButton buttonCancel;
    private JComboBox comboBoxSigningKey;
    private SignedToken tokenObject;

    public SignDialog(Window parent,
                      ErrorLoggingActionListenerFactory actionListenerFactory,
                      List<SecretKey> signingKeys,
                      SignedToken tokenObject) {
        super(parent, "sign_dialog_title");
        this.tokenObject = tokenObject;

        setContentPane(contentPane);
        getRootPane().setDefaultButton(buttonOK);

        buttonOK.addActionListener(actionListenerFactory.from(e -> onOK()));
        buttonCancel.addActionListener(e -> onCancel());

        contentPane.registerKeyboardAction(
                e -> onCancel(),
                KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
                JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT
        );

        SecretKey[] signingKeysArray = new SecretKey[signingKeys.size()];
        signingKeys.toArray(signingKeysArray);

        comboBoxSigningKey.setModel(new DefaultComboBoxModel<>(signingKeysArray));
        comboBoxSigningKey.setSelectedIndex(0);
    }

    private void onOK() {
        SecretKey selectedKey = (SecretKey) comboBoxSigningKey.getSelectedItem();

        try {
            assert selectedKey != null;
            TokenSigner s;
            if (tokenObject instanceof DangerousSignedToken) {
                s = new DangerousTokenSigner(selectedKey);
            } else if (tokenObject instanceof ExpressSignedToken) {
                s = new ExpressTokenSigner(selectedKey);
            } else if (tokenObject instanceof OauthProxySignedToken) {
                s = new OauthProxyTokenSigner(selectedKey);
            } else if (tokenObject instanceof TornadoSignedToken) {
                s = new TornadoTokenSigner(selectedKey);
            } else {
                throw new Exception("Unknown");
            }
            tokenObject.setSigner(s);
            tokenObject.resign();
        } catch (Exception e) {
            tokenObject = null;
            JOptionPane.showMessageDialog(
                    this,
                    e.getMessage(),
                    Utils.getResourceString("error_title_unable_to_sign"),
                    WARNING_MESSAGE
            );
        } finally {
            dispose();
        }
    }

    public SignedToken getToken() {
        return tokenObject;
    }


}
