package one.d4d.sessionless.forms.dialog;

import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.CollaboratorPayloadGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import one.d4d.sessionless.itsdangerous.crypto.*;
import one.d4d.sessionless.itsdangerous.model.*;
import one.d4d.sessionless.keys.SecretKey;
import one.d4d.sessionless.utils.ClaimsUtils;
import one.d4d.sessionless.utils.ErrorLoggingActionListenerFactory;
import one.d4d.sessionless.utils.Utils;

import javax.swing.*;
import java.awt.*;
import java.awt.event.KeyEvent;
import java.net.URL;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

import static javax.swing.JOptionPane.WARNING_MESSAGE;

public class AttackDialog extends AbstractDialog {
    private final URL targetURL;
    private final CollaboratorPayloadGenerator collaboratorPayloadGenerator;
    private JPanel contentPane;
    private JButton buttonOK;
    private JButton buttonCancel;
    private JCheckBox checkBoxUserClaims;
    private JCheckBox checkBoxUserWrappedClaims;
    private JCheckBox checkBoxUsernamePasswordClaims;
    private JCheckBox checkBoxFlaskClaims;
    private JCheckBox checkBoxExpressClaims;
    private JCheckBox checkBoxAccountUserClaims;
    private JCheckBox checkBoxAuthenticatedClaims;
    private JComboBox comboBoxSigningKey;
    private JCheckBox checkBoxUserAccessToken;
    private SignedToken tokenObject;

    public AttackDialog(
            Window parent,
            ErrorLoggingActionListenerFactory actionListenerFactory,
            List<SecretKey> signingKeys,
            URL targetURL,
            CollaboratorPayloadGenerator collaboratorPayloadGenerator,
            SignedToken tokenObject) {
        super(parent, "sign_dialog_title");
        this.tokenObject = tokenObject;
        this.collaboratorPayloadGenerator = collaboratorPayloadGenerator;
        this.targetURL = targetURL;

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

    private JWTClaimsSet checkInput(SecretKey selectedKey) {
        String payload = String.format("https://%s/", collaboratorPayloadGenerator.generatePayload().toString());
        List<JWTClaimsSet> args = new ArrayList<>();
        if (checkBoxUserClaims.isSelected()) {
            args.add(ClaimsUtils.generateUserClaim(targetURL, payload));
        }
        if (checkBoxUserWrappedClaims.isSelected()) {
            args.add(ClaimsUtils.generateUserPayload(targetURL));
        }
        if (checkBoxUsernamePasswordClaims.isSelected()) {
            args.add(ClaimsUtils.generateUserPasswordPayload(targetURL));
        }
        if (checkBoxFlaskClaims.isSelected()) {
            args.add(ClaimsUtils.generateFlaskUserPayload(targetURL));
        }
        if (checkBoxExpressClaims.isSelected()) {
            args.add(ClaimsUtils.generateExpressUserPayload());
        }
        if (checkBoxAccountUserClaims.isSelected()) {
            args.add(ClaimsUtils.generateAccountUserPayload(targetURL));
        }
        if (checkBoxAuthenticatedClaims.isSelected()) {
            args.add(ClaimsUtils.generateAuthenticatedClaims());
        }
        if (checkBoxUserAccessToken.isSelected()) {
            args.add(ClaimsUtils.generateUserAccessTokenPayload(targetURL, selectedKey));
        }
        try {
            return ClaimsUtils.concatClaims(args);
        } catch (ParseException e) {
            JOptionPane.showMessageDialog(
                    this,
                    e.getMessage(),
                    Utils.getResourceString("error_title_unable_to_sign"),
                    WARNING_MESSAGE
            );
        }
        return null;
    }

    private void onOK() {
        SecretKey selectedKey = (SecretKey) comboBoxSigningKey.getSelectedItem();
        JWTClaimsSet selectedClaims = checkInput(selectedKey);

        try {
            assert selectedClaims != null;
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
            } else if (tokenObject instanceof JSONWebSignature) {
                s = new JSONWebSignatureTokenSigner(selectedKey);
            } else if (tokenObject instanceof UnknownSignedToken) {
                s = new TokenSigner(selectedKey);
            } else {
                throw new Exception("Unknown");
            }
            tokenObject.setClaims(selectedClaims);
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
