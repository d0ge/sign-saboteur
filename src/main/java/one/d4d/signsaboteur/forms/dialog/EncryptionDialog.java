package one.d4d.signsaboteur.forms.dialog;

import one.d4d.signsaboteur.itsdangerous.crypto.*;
import one.d4d.signsaboteur.itsdangerous.model.*;
import one.d4d.signsaboteur.keys.SecretKey;
import one.d4d.signsaboteur.rsta.RstaFactory;
import one.d4d.signsaboteur.utils.ErrorLoggingActionListenerFactory;
import one.d4d.signsaboteur.utils.Utils;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.LineBorder;
import java.awt.*;
import java.awt.event.*;
import java.util.List;

import static java.awt.Color.RED;
import static javax.swing.JOptionPane.WARNING_MESSAGE;

public class EncryptionDialog extends AbstractDialog {
    private JPanel contentPane;
    private JButton buttonOK;
    private JButton buttonCancel;
    private JComboBox comboBoxEncryptionKeys;
    private RSyntaxTextArea cypherText;
    private SignedToken tokenObject;
    private RstaFactory rstaFactory;

    public EncryptionDialog(Window parent,
                            RstaFactory rstaFactory,
                            ErrorLoggingActionListenerFactory actionListenerFactory,
                            List<SecretKey> signingKeys,
                            SignedToken tokenObject) {
        super(parent, "encryption_dialog_title");
        this.rstaFactory = rstaFactory;
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

        comboBoxEncryptionKeys.setModel(new DefaultComboBoxModel<>(signingKeysArray));
        comboBoxEncryptionKeys.setSelectedIndex(0);
    }

    private void onOK() {
        SecretKey selectedKey = (SecretKey) comboBoxEncryptionKeys.getSelectedItem();

        try {
            assert selectedKey != null;
            TokenSigner s;
            if (tokenObject instanceof RubyEncryptedToken) {
                s = new RubyEncryptionTokenSigner(selectedKey);
            } else {
                throw new Exception("Unknown");
            }
            tokenObject.setSigner(s);
            String text = ((RubyEncryptedToken) tokenObject).getCypherText();
            cypherText.setText(text);

            Border serializedTextAreaBorder = text.equals("Error") ? new LineBorder(RED, 1) : null;
            cypherText.setBorder(serializedTextAreaBorder);
        } catch (Exception e) {
            tokenObject = null;
            JOptionPane.showMessageDialog(
                    this,
                    e.getMessage(),
                    Utils.getResourceString("error_title_unable_to_sign"),
                    WARNING_MESSAGE
            );
        }
    }

    private void createUIComponents() {
        // TODO: place custom component creation code here
        cypherText = rstaFactory.buildDefaultTextArea();
    }
}
