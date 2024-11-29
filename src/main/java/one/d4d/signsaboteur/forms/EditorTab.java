package one.d4d.signsaboteur.forms;

import burp.api.montoya.collaborator.CollaboratorPayloadGenerator;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedEditor;
import burp.config.SignerConfig;
import one.d4d.signsaboteur.forms.utils.FormUtils;
import one.d4d.signsaboteur.hexcodearea.HexCodeAreaFactory;
import one.d4d.signsaboteur.presenter.EditorPresenter;
import one.d4d.signsaboteur.presenter.PresenterStore;
import one.d4d.signsaboteur.rsta.RstaFactory;
import one.d4d.signsaboteur.utils.ErrorLoggingActionListenerFactory;
import one.d4d.signsaboteur.utils.MaxLengthStringComboBoxModel;
import one.d4d.signsaboteur.utils.Utils;
import org.exbin.deltahex.EditationAllowed;
import org.exbin.deltahex.swing.CodeArea;
import org.exbin.utils.binary_data.ByteArrayEditableData;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.LineBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.util.List;

import static java.awt.Color.RED;
import static org.exbin.deltahex.EditationAllowed.ALLOWED;
import static org.exbin.deltahex.EditationAllowed.READ_ONLY;

public abstract class EditorTab implements ExtensionProvidedEditor {
    public static final int TAB_DANGEROUS = 0;
    public static final int TAB_EXPRESS = 1;
    public static final int TAB_OAUTH = 2;
    public static final int TAB_TORNADO = 3;
    public static final int TAB_RUBY = 4;
    public static final int TAB_JWT = 5;
    public static final int TAB_UNKNOWN = 6;
    private static final int MAX_JOSE_OBJECT_STRING_LENGTH = 68;
    final EditorPresenter presenter;
    private final RstaFactory rstaFactory;
    private final boolean editable;
    private final HexCodeAreaFactory hexCodeAreaFactory;
    private final boolean isProVersion;
    private final SignerConfig signerConfig;
    private int mode;
    private JPanel mainPanel;
    private JTabbedPane tabbedPane;
    private JComboBox<String> comboBoxSignedToken;
    private RSyntaxTextArea textAreaSignedToken;
    private RSyntaxTextArea textAreaDangerousPayload;
    private JPanel panelDangerousSignature;
    private RSyntaxTextArea textAreaExpressPayload;
    private JButton buttonBruteForceAttack;
    private JPanel panelDangerousSeparator;
    private RSyntaxTextArea textAreaDangerousTimestamp;
    private JButton buttonSign;
    private RSyntaxTextArea textAreaOAuthPayload;
    private RSyntaxTextArea textAreaOAuthTimeStamp;
    private JPanel panelOAuthSignature;
    private RSyntaxTextArea textAreaOAuthParameter;
    private RSyntaxTextArea textAreaExpressParameter;
    private JButton buttonCopyExpressSignature;
    private RSyntaxTextArea textAreaExpressSignature;
    private JPanel panelTornadoSignature;
    private RSyntaxTextArea textAreaTornadoTimestamp;
    private RSyntaxTextArea textAreaTornadoName;
    private RSyntaxTextArea textAreaTornadoValue;
    private JCheckBox checkBoxIsJSON;
    private JCheckBox checkBoxDjango;
    private JCheckBox checkBoxCompress;
    private JButton buttonAttack;
    private RSyntaxTextArea textAreaUnknownStringMessage;
    private JPanel panelUnknownStringSeparator;
    private RSyntaxTextArea textAreaUnknownStringSignature;
    private JPanel panelRubySeparator;
    private RSyntaxTextArea textAreaRubyMessage;
    private RSyntaxTextArea textAreaRubySignature;
    private JPanel panelJSONWebSignature;
    private JPanel panelJSONWebSeparator;
    private RSyntaxTextArea textAreaJSONWebSignatureHeader;
    private RSyntaxTextArea textAreaJSONWebSignaturePayload;
    private JCheckBox checkBoxUnknownURLEncoded;
    private JCheckBox checkBoxRubyURLEncoded;
    private JButton decryptButton;
    private CodeArea codeAreaDangerousSignature;
    private CodeArea codeAreaDangerousSeparator;
    private CodeArea codeAreaOAuthSignature;
    private CodeArea codeAreaTornadoSignature;
    private CodeArea codeAreaRubySeparator;
    private CodeArea codeAreaJWTSignature;
    private CodeArea codeAreaJWTSeparator;
    private CodeArea codeAreaUnknownSeparator;

    EditorTab(
            PresenterStore presenters,
            RstaFactory rstaFactory,
            HexCodeAreaFactory hexAreaCodeFactory,
            CollaboratorPayloadGenerator collaboratorPayloadGenerator,
            ErrorLoggingActionListenerFactory actionListenerFactory,
            SignerConfig signerConfig,
            boolean editable,
            boolean isProVersion) {
        this.rstaFactory = rstaFactory;
        this.editable = editable;
        this.hexCodeAreaFactory = hexAreaCodeFactory;
        this.isProVersion = isProVersion;
        this.signerConfig = signerConfig;
        this.presenter = new EditorPresenter(
                this,
                rstaFactory,
                collaboratorPayloadGenerator,
                actionListenerFactory,
                presenters,
                signerConfig);

        DocumentListener documentListener = new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                presenter.componentChanged();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                presenter.componentChanged();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                presenter.componentChanged();
            }
        };

        textAreaDangerousPayload.getDocument().addDocumentListener(documentListener);
        textAreaDangerousTimestamp.getDocument().addDocumentListener(documentListener);
        textAreaExpressParameter.getDocument().addDocumentListener(documentListener);
        textAreaExpressPayload.getDocument().addDocumentListener(documentListener);
        textAreaExpressSignature.getDocument().addDocumentListener(documentListener);
        textAreaOAuthParameter.getDocument().addDocumentListener(documentListener);
        textAreaOAuthPayload.getDocument().addDocumentListener(documentListener);
        textAreaOAuthTimeStamp.getDocument().addDocumentListener(documentListener);
        textAreaTornadoTimestamp.getDocument().addDocumentListener(documentListener);
        textAreaTornadoName.getDocument().addDocumentListener(documentListener);
        textAreaTornadoValue.getDocument().addDocumentListener(documentListener);
        textAreaRubyMessage.getDocument().addDocumentListener(documentListener);
        textAreaRubySignature.getDocument().addDocumentListener(documentListener);
        textAreaJSONWebSignatureHeader.getDocument().addDocumentListener(documentListener);
        textAreaJSONWebSignaturePayload.getDocument().addDocumentListener(documentListener);
        textAreaUnknownStringMessage.getDocument().addDocumentListener(documentListener);
        textAreaUnknownStringSignature.getDocument().addDocumentListener(documentListener);

        checkBoxIsJSON.addActionListener(e -> presenter.componentChanged());
        checkBoxDjango.addActionListener(e -> presenter.componentChanged());
        checkBoxCompress.addActionListener(e -> presenter.componentChanged());
        checkBoxRubyURLEncoded.addActionListener(e -> presenter.componentChanged());
        checkBoxUnknownURLEncoded.addActionListener(e -> presenter.componentChanged());

        codeAreaDangerousSignature.addDataChangedListener(presenter::componentChanged);
        codeAreaDangerousSeparator.addDataChangedListener(presenter::componentChanged);
        codeAreaOAuthSignature.addDataChangedListener(presenter::componentChanged);
        codeAreaTornadoSignature.addDataChangedListener(presenter::componentChanged);
        codeAreaRubySeparator.addDataChangedListener(presenter::componentChanged);
        codeAreaJWTSignature.addDataChangedListener(presenter::componentChanged);
        codeAreaJWTSeparator.addDataChangedListener(presenter::componentChanged);
        codeAreaUnknownSeparator.addDataChangedListener(presenter::componentChanged);

        comboBoxSignedToken.addActionListener(e -> presenter.onSelectionChanged());

        buttonSign.addActionListener(e -> presenter.onSignClicked());
        buttonAttack.addActionListener(e -> presenter.onAttackClicked());
        buttonCopyExpressSignature.addActionListener(e -> presenter.copyExpressSignature());
        decryptButton.addActionListener(e -> presenter.decryptRubyMessage());
    }

    public Window window() {
        return SwingUtilities.getWindowAncestor(mainPanel);
    }

    public int getMode() {
        return mode;
    }

    public int getSelectedSignedTokenObjectIndex() {
        return comboBoxSignedToken.getSelectedIndex();
    }

    public void setSignedToken(String text, boolean textModified) {
        textAreaSignedToken.setText(text);

        Border serializedTextAreaBorder = textModified ? new LineBorder(RED, 1) : null;
        textAreaSignedToken.setBorder(serializedTextAreaBorder);
    }

    public String getExpressPayload() {
        return textAreaExpressPayload.getText();
    }

    public void setExpressPayload(String payload) {
        textAreaExpressPayload.setText(payload);
    }

    public String getExpressParameter() {
        return textAreaExpressParameter.getText();
    }

    public void setExpressParameter(String parameter) {
        textAreaExpressParameter.setText(parameter);
    }

    public String getDangerousPayload() {
        return textAreaDangerousPayload.getText();
    }

    public void setDangerousPayload(String header) {
        textAreaDangerousPayload.setText(header);
    }

    public String getOAuthParameter() {
        return textAreaOAuthParameter.getText();
    }

    public void setOAuthParameter(String text) {
        textAreaOAuthParameter.setText(text);
    }

    public String getOAuthPayload() {
        return textAreaOAuthPayload.getText();
    }

    public void setOAuthPayload(String text) {
        textAreaOAuthPayload.setText(text);
    }

    public String getExpressSignature() {
        return textAreaExpressSignature.getText();
    }

    public void setExpressSignature(String text) {
        textAreaExpressSignature.setText(text);
    }

    public byte[] getOAuthSignature() {
        return FormUtils.getCodeAreaData(codeAreaOAuthSignature);
    }

    public void setOAuthSignature(byte[] signature) {
        codeAreaOAuthSignature.setData(new ByteArrayEditableData(signature));
    }

    public String getTornadoName() {
        return textAreaTornadoName.getText();
    }

    public void setTornadoName(String payload) {
        textAreaTornadoName.setText(payload);
    }

    public String getTornadoValue() {
        return textAreaTornadoValue.getText();
    }

    public void setTornadoValue(String parameter) {
        textAreaTornadoValue.setText(parameter);
    }

    public String getTornadoTimestamp() {
        return textAreaTornadoTimestamp.getText();
    }

    public void setTornadoTimestamp(String parameter) {
        textAreaTornadoTimestamp.setText(parameter);
    }

    public byte[] getTornadoSignature() {
        return FormUtils.getCodeAreaData(codeAreaTornadoSignature);
    }

    public void setTornadoSignature(byte[] signature) {
        codeAreaTornadoSignature.setData(new ByteArrayEditableData(signature));
    }

    public byte[] getDangerousSignature() {
        return FormUtils.getCodeAreaData(codeAreaDangerousSignature);
    }

    public void setDangerousSignature(byte[] signature) {
        codeAreaDangerousSignature.setData(new ByteArrayEditableData(signature));
    }

    public String getDangerousTimestamp() {
        return textAreaDangerousTimestamp.getText();
    }

    public void setDangerousTimestamp(String timestamp) {
        textAreaDangerousTimestamp.setText(timestamp);
    }

    public String getOAuthTimestamp() {
        return textAreaOAuthTimeStamp.getText();
    }

    public void setOAuthTimestamp(String timestamp) {
        textAreaOAuthTimeStamp.setText(timestamp);
    }

    public byte[] getDangerousSeparator() {
        return FormUtils.getCodeAreaData(codeAreaDangerousSeparator);
    }

    public void setDangerousSeparator(byte[] separator) {
        codeAreaDangerousSeparator.setData(new ByteArrayEditableData(separator));
    }

    public boolean getDangerouseIsJSON() {
        return checkBoxIsJSON.isSelected();
    }

    public void setDangerouseIsJSON(boolean enabled) {
        checkBoxIsJSON.setSelected(enabled);
    }

    public boolean getDangerouseIsDjangoFormatting() {
        return checkBoxDjango.isSelected();
    }

    public void setDangerouseIsDjangoFormatting(boolean enabled) {
        checkBoxDjango.setSelected(enabled);
    }

    public boolean getDangerouseIsCompressed() {
        return checkBoxCompress.isSelected();
    }

    public void setDangerouseIsCompressed(boolean enabled) {
        checkBoxCompress.setSelected(enabled);
    }

    public String getRubyMessage() {
        return textAreaRubyMessage.getText();
    }

    public void setRubyMessage(String text) {
        textAreaRubyMessage.setText(text);
    }

    public boolean getRubyIsURLEncoded() {
        return checkBoxRubyURLEncoded.isSelected();
    }
    public boolean getRubyIsEncrypted() {
        return decryptButton.isEnabled();
    }

    public void setRubyIsURLEncoded(boolean enabled) {
        checkBoxRubyURLEncoded.setSelected(enabled);
    }

    public String getRubySignature() {
        return textAreaRubySignature.getText();
    }

    public void setRubySignature(String signature) {
        textAreaRubySignature.setText(signature);
    }

    public byte[] getRubySeparator() {
        return FormUtils.getCodeAreaData(codeAreaRubySeparator);
    }

    public void setRubySeparator(byte[] separator) {
        codeAreaRubySeparator.setData(new ByteArrayEditableData(separator));
    }

    public void setRubyDecryptButton(boolean enabled) {
        decryptButton.setEnabled(enabled);
    }

    public String getJWTHeader() {
        return textAreaJSONWebSignatureHeader.getText();
    }

    public void setJWTHeader(String text) {
        textAreaJSONWebSignatureHeader.setText(text);
    }

    public String getJWTPayload() {
        return textAreaJSONWebSignaturePayload.getText();
    }

    public void setJWTPayload(String text) {
        textAreaJSONWebSignaturePayload.setText(text);
    }

    public byte[] getJWTSignature() {
        return FormUtils.getCodeAreaData(codeAreaJWTSignature);
    }

    public void setJWTSignature(byte[] separator) {
        codeAreaJWTSignature.setData(new ByteArrayEditableData(separator));
    }

    public byte[] getJWTSeparator() {
        return FormUtils.getCodeAreaData(codeAreaJWTSeparator);
    }

    public void setJWTSeparator(byte[] separator) {
        codeAreaJWTSeparator.setData(new ByteArrayEditableData(separator));
    }

    public String getUnknownMessage() {
        return textAreaUnknownStringMessage.getText();
    }

    public void setUnknownMessage(String text) {
        textAreaUnknownStringMessage.setText(text);
    }
    public boolean getUnknownIsURLEncoded() {
        return checkBoxUnknownURLEncoded.isSelected();
    }

    public void setUnknownIsURLEncoded(boolean enabled) {
        checkBoxUnknownURLEncoded.setSelected(enabled);
    }


    public String getUnknownSignature() {
        return textAreaUnknownStringSignature.getText();
    }

    public void setUnknownSignature(String signature) {
        textAreaUnknownStringSignature.setText(signature);
    }

    public byte[] getUnknownSeparator() {
        return FormUtils.getCodeAreaData(codeAreaUnknownSeparator);
    }

    public void setUnknownSeparator(byte[] separator) {
        codeAreaUnknownSeparator.setData(new ByteArrayEditableData(separator));
    }

    public void setSignedTokenObjects(List<String> signedTokenObjectStrings) {
        comboBoxSignedToken.setModel(new MaxLengthStringComboBoxModel(MAX_JOSE_OBJECT_STRING_LENGTH, signedTokenObjectStrings));

        if (signedTokenObjectStrings.size() > 0) {
            comboBoxSignedToken.setSelectedIndex(0);
        }
    }

    private void createUIComponents() {

        panelDangerousSignature = new JPanel(new BorderLayout());
        codeAreaDangerousSignature = hexCodeAreaFactory.build();
        panelDangerousSignature.add(codeAreaDangerousSignature);

        panelDangerousSeparator = new JPanel(new BorderLayout());
        codeAreaDangerousSeparator = hexCodeAreaFactory.build();
        panelDangerousSeparator.add(codeAreaDangerousSeparator);

        panelOAuthSignature = new JPanel(new BorderLayout());
        codeAreaOAuthSignature = hexCodeAreaFactory.build();
        panelOAuthSignature.add(codeAreaOAuthSignature);

        panelTornadoSignature = new JPanel(new BorderLayout());
        codeAreaTornadoSignature = hexCodeAreaFactory.build();
        panelTornadoSignature.add(codeAreaTornadoSignature);

        panelRubySeparator = new JPanel(new BorderLayout());
        codeAreaRubySeparator = hexCodeAreaFactory.build();
        panelRubySeparator.add(codeAreaRubySeparator);

        panelJSONWebSignature = new JPanel(new BorderLayout());
        codeAreaJWTSignature = hexCodeAreaFactory.build();
        panelJSONWebSignature.add(codeAreaJWTSignature);

        panelJSONWebSeparator = new JPanel(new BorderLayout());
        codeAreaJWTSeparator = hexCodeAreaFactory.build();
        panelJSONWebSeparator.add(codeAreaJWTSeparator);

        panelUnknownStringSeparator = new JPanel(new BorderLayout());
        codeAreaUnknownSeparator = hexCodeAreaFactory.build();
        panelUnknownStringSeparator.add(codeAreaUnknownSeparator);

        // Create the Attack popup menu
        JPopupMenu popupMenuAttack = new JPopupMenu();
        JMenuItem menuItemAttackBruteForceKnownKeys = new JMenuItem(Utils.getResourceString("editor_view_button_attack_known_keys"));
        JMenuItem menuItemAttackBruteForce = new JMenuItem(Utils.getResourceString("editor_view_button_attack_fast"));
        JMenuItem menuItemAttackBruteForceBalanced = new JMenuItem(Utils.getResourceString("editor_view_button_attack_balanced"));
        JMenuItem menuItemAttackBruteForceDeep = new JMenuItem(Utils.getResourceString("editor_view_button_attack_deep"));

        // Attach the event handlers to the popup menu click events
        menuItemAttackBruteForceKnownKeys.addActionListener(e -> presenter.onAttackKnownKeysClicked());
        menuItemAttackBruteForce.addActionListener(e -> presenter.onAttackFastClicked());
        menuItemAttackBruteForceBalanced.addActionListener(e -> presenter.onAttackBalancedClicked());
        menuItemAttackBruteForceDeep.addActionListener(e -> presenter.onAttackDeepClicked());


        // Add the buttons to the popup menu
        popupMenuAttack.add(menuItemAttackBruteForceKnownKeys);
        popupMenuAttack.add(menuItemAttackBruteForce);
        popupMenuAttack.add(menuItemAttackBruteForceBalanced);
        popupMenuAttack.add(menuItemAttackBruteForceDeep);

        // Associate the popup menu to the Attack button
        buttonBruteForceAttack = new JButton();
        buttonBruteForceAttack.setComponentPopupMenu(popupMenuAttack);


        buttonBruteForceAttack.addActionListener(e -> onBruteForceAttackClicked());

        textAreaSignedToken = rstaFactory.buildSerializedJWTTextArea();
        textAreaDangerousPayload = rstaFactory.buildDefaultTextArea();
        textAreaDangerousTimestamp = rstaFactory.buildDefaultTextArea();
        textAreaExpressParameter = rstaFactory.buildDefaultTextArea();
        textAreaExpressPayload = rstaFactory.buildDefaultTextArea();
        textAreaExpressSignature = rstaFactory.buildDefaultTextArea();
        textAreaOAuthParameter = rstaFactory.buildDefaultTextArea();
        textAreaOAuthPayload = rstaFactory.buildDefaultTextArea();
        textAreaOAuthTimeStamp = rstaFactory.buildDefaultTextArea();
        textAreaTornadoTimestamp = rstaFactory.buildDefaultTextArea();
        textAreaTornadoName = rstaFactory.buildDefaultTextArea();
        textAreaTornadoValue = rstaFactory.buildDefaultTextArea();
        textAreaRubyMessage = rstaFactory.buildDefaultTextArea();
        textAreaRubySignature = rstaFactory.buildDefaultTextArea();
        textAreaJSONWebSignatureHeader = rstaFactory.buildDefaultTextArea();
        textAreaJSONWebSignaturePayload = rstaFactory.buildDefaultTextArea();
        textAreaUnknownStringMessage = rstaFactory.buildDefaultTextArea();
        textAreaUnknownStringSignature = rstaFactory.buildDefaultTextArea();
    }

    private void onBruteForceAttackClicked() {
        // Display the attack popup menu
        JPopupMenu popupMenu = buttonBruteForceAttack.getComponentPopupMenu();
        popupMenu.setVisible(false);
        // Position to above attack button
        buttonBruteForceAttack.getComponentPopupMenu().show(buttonBruteForceAttack, buttonBruteForceAttack.getX(), buttonBruteForceAttack.getY());
        buttonBruteForceAttack.getComponentPopupMenu().show(
                buttonBruteForceAttack,
                buttonBruteForceAttack.getX(),
                buttonBruteForceAttack.getY() - buttonBruteForceAttack.getComponentPopupMenu().getHeight()
        );
    }

    private void enableTabAtIndex(int index) {
        tabbedPane.setSelectedIndex(index);
        for (int i = 0; i < tabbedPane.getTabCount(); i++) {
            tabbedPane.setEnabledAt(i, i == index);
        }
    }

    public void setDangerousMode() {
        mode = TAB_DANGEROUS;
        enableTabAtIndex(TAB_DANGEROUS);
        buttonAttack.setEnabled(editable);
        textAreaDangerousPayload.setEditable(editable);
        textAreaDangerousTimestamp.setEditable(editable);
        checkBoxIsJSON.setEnabled(editable);
        checkBoxDjango.setEnabled(false);
        checkBoxCompress.setEnabled(editable);
        checkBoxIsJSON.setSelected(false);
        checkBoxDjango.setSelected(false);
        checkBoxCompress.setSelected(false);

        EditationAllowed editationAllowed = editable ? ALLOWED : READ_ONLY;

        codeAreaDangerousSignature.setEditationAllowed(editationAllowed);
        codeAreaDangerousSeparator.setEditationAllowed(editationAllowed);

    }

    public void setExpressMode() {
        mode = TAB_EXPRESS;
        enableTabAtIndex(TAB_EXPRESS);
        buttonAttack.setEnabled(editable);
        textAreaExpressParameter.setEditable(false);
        textAreaExpressPayload.setEditable(editable);
        textAreaExpressSignature.setEditable(editable);
    }

    public void setOAuthMode() {
        mode = TAB_OAUTH;
        enableTabAtIndex(TAB_OAUTH);
        buttonAttack.setEnabled(false);
        textAreaOAuthParameter.setEditable(false);
        textAreaOAuthPayload.setEditable(editable);
        textAreaOAuthTimeStamp.setEditable(editable);

        EditationAllowed editationAllowed = editable ? ALLOWED : READ_ONLY;
        codeAreaOAuthSignature.setEditationAllowed(editationAllowed);
    }

    public void setTornadoMode() {
        mode = TAB_TORNADO;
        enableTabAtIndex(TAB_TORNADO);
        buttonAttack.setEnabled(editable);

        textAreaTornadoTimestamp.setEditable(editable);
        textAreaTornadoName.setEditable(editable);
        textAreaTornadoValue.setEditable(editable);

        EditationAllowed editationAllowed = editable ? ALLOWED : READ_ONLY;
        codeAreaTornadoSignature.setEditationAllowed(editationAllowed);
    }

    public void setRubyMode() {
        mode = TAB_RUBY;
        enableTabAtIndex(TAB_RUBY);
        checkBoxRubyURLEncoded.setEnabled(editable);
        buttonAttack.setEnabled(editable);

        textAreaRubyMessage.setEditable(editable);
        textAreaRubySignature.setEditable(editable);

        EditationAllowed editationAllowed = editable ? ALLOWED : READ_ONLY;
        codeAreaRubySeparator.setEditationAllowed(editationAllowed);
    }

    public void setJWTMode() {
        mode = TAB_JWT;
        enableTabAtIndex(TAB_JWT);
        buttonAttack.setEnabled(editable);

        textAreaJSONWebSignatureHeader.setEditable(editable);
        textAreaJSONWebSignaturePayload.setEditable(editable);

        EditationAllowed editationAllowed = editable ? ALLOWED : READ_ONLY;
        codeAreaJWTSignature.setEditationAllowed(editationAllowed);
        codeAreaJWTSeparator.setEditationAllowed(editationAllowed);
    }

    public void setUnknownMode() {
        mode = TAB_UNKNOWN;
        enableTabAtIndex(TAB_UNKNOWN);
        checkBoxUnknownURLEncoded.setEnabled(editable);
        buttonAttack.setEnabled(editable);

        textAreaUnknownStringMessage.setEditable(editable);
        textAreaUnknownStringSignature.setEditable(editable);

        EditationAllowed editationAllowed = editable ? ALLOWED : READ_ONLY;
        codeAreaUnknownSeparator.setEditationAllowed(editationAllowed);
    }

    @Override
    public String caption() {
        return Utils.getResourceString("burp_editor_tab");
    }

    public Component uiComponent() {
        return mainPanel;
    }

    @Override
    public Selection selectedData() {
        return null;
    }

    @Override
    public boolean isModified() {
        return presenter.isModified();
    }
}
