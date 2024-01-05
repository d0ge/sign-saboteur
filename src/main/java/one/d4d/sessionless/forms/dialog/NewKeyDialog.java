package one.d4d.sessionless.forms.dialog;

import one.d4d.sessionless.itsdangerous.Algorithms;
import one.d4d.sessionless.itsdangerous.Derivation;
import one.d4d.sessionless.itsdangerous.MessageDerivation;
import one.d4d.sessionless.itsdangerous.MessageDigestAlgorithm;
import one.d4d.sessionless.keys.Key;
import one.d4d.sessionless.keys.SecretKey;
import one.d4d.sessionless.presenter.PresenterStore;
import one.d4d.sessionless.utils.DocumentAdapter;
import one.d4d.sessionless.utils.GsonHelper;

import javax.swing.*;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.KeyEvent;
import java.util.UUID;

public class NewKeyDialog extends KeyDialog {
    private static final String TITLE_RESOURCE_ID = "new_key_dialog_title";
    private JPanel contentPane;
    private JButton buttonOK;
    private JButton buttonCancel;
    private JComboBox comboBoxAlgorythm;
    private JComboBox comboBoxDigest;
    private JComboBox comboBoxDerivation;
    private JTextField textFieldSecretKey;
    private JTextField textFieldSeparator;
    private JTextField textFieldSalt;
    private JTextField textFieldKeyID;
    private JCheckBox checkBoxSecretJSON;
    private JCheckBox checkBoxSaltJSON;
    private JComboBox comboBoxMessageDerivation;

    private SecretKey key;

    public NewKeyDialog(Window parent, PresenterStore presenters) {
        this(
                parent,
                presenters,
                true,
                UUID.randomUUID().toString(),
                "",
                "",
                "",
                Algorithms.SHA1,
                Derivation.HMAC,
                MessageDerivation.NONE,
                MessageDigestAlgorithm.SHA1);
        originalId = null;
    }

    public NewKeyDialog(Window parent, PresenterStore presenters, SecretKey key) {
        this(
                parent,
                presenters,
                true,
                key.getID(),
                key.getSecret(),
                key.getSalt(),
                key.getSeparator(),
                key.getDigestMethod(),
                key.getKeyDerivation(),
                key.getMessageDerivation(),
                key.getMessageDigestAlgorythm()
        );
    }

    private NewKeyDialog(
            Window parent,
            PresenterStore presenters,
            boolean encodeJSON,
            String keyId,
            String secret,
            String salt,
            String separator,
            Algorithms algorithms,
            Derivation derivation,
            MessageDerivation messageDerivation,
            MessageDigestAlgorithm digest) {
        super(parent, TITLE_RESOURCE_ID);
        this.presenters = presenters;
        originalId = keyId;

        setContentPane(contentPane);
        getRootPane().setDefaultButton(buttonOK);

        buttonOK.addActionListener(e -> onOK());
        buttonCancel.addActionListener(e -> onCancel());

        contentPane.registerKeyboardAction(e -> onCancel(), KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);

        DocumentListener documentListener = new DocumentAdapter(e -> checkInput());

        textFieldSecretKey.getDocument().addDocumentListener(documentListener);
        textFieldSalt.getDocument().addDocumentListener(documentListener);
        textFieldKeyID.getDocument().addDocumentListener(documentListener);

        textFieldKeyID.setText(keyId);
        if (encodeJSON) {
            textFieldSecretKey.setText(GsonHelper.customGson.toJson(secret));
            textFieldSalt.setText(GsonHelper.customGson.toJson(salt));
            checkBoxSecretJSON.setSelected(true);
            checkBoxSaltJSON.setSelected(true);
        }else {
            textFieldSecretKey.setText(secret);
            textFieldSalt.setText(salt);
        }
        textFieldSeparator.setText(separator);

        comboBoxAlgorythm.setModel(new DefaultComboBoxModel<>(Algorithms.values()));
        comboBoxAlgorythm.setSelectedItem(algorithms);
        comboBoxDigest.setModel(new DefaultComboBoxModel<>(MessageDigestAlgorithm.values()));
        comboBoxDigest.setSelectedItem(digest);
        comboBoxDerivation.setModel(new DefaultComboBoxModel<>(Derivation.values()));
        comboBoxDerivation.setSelectedItem(derivation);
        comboBoxMessageDerivation.setModel(new DefaultComboBoxModel<>(MessageDerivation.values()));
        comboBoxMessageDerivation.setSelectedItem(messageDerivation);
    }

    private void checkInput() {
        buttonOK.setEnabled(textFieldKeyID.getText().length() > 0 &&
                textFieldSecretKey.getText().length() > 0);
    }

    @Override
    void onOK() {
        String secret = textFieldSecretKey.getText();
        if (checkBoxSecretJSON.isSelected()) {
            secret = GsonHelper.customGson.fromJson(secret, String.class);
        }
        String salt = textFieldSalt.getText();
        if (checkBoxSecretJSON.isSelected()) {
            salt = GsonHelper.customGson.fromJson(salt, String.class);
        }
        key = new SecretKey(
                textFieldKeyID.getText(),
                secret,
                salt,
                textFieldSeparator.getText(),
                (Algorithms) comboBoxAlgorythm.getSelectedItem(),
                (Derivation) comboBoxDerivation.getSelectedItem(),
                (MessageDerivation) comboBoxMessageDerivation.getSelectedItem(),
                (MessageDigestAlgorithm) comboBoxDigest.getSelectedItem()
        );
        super.onOK();
    }

    @Override
    void onCancel() {
        key = null;
        dispose();
    }

    @Override
    public Key getKey() {
        return key;
    }

}
