package one.d4d.sessionless.forms;

import burp.api.montoya.ui.UserInterface;
import burp.config.BurpConfig;
import burp.config.ProxyConfig;
import burp.config.SignerConfig;
import burp.proxy.HighlightColor;
import one.d4d.sessionless.itsdangerous.crypto.Signers;

import javax.swing.*;
import java.awt.*;

import static java.awt.Font.BOLD;

public class SettingsView {
    private final Window parent;
    private JPanel mainPanel;
    private JPanel proxyPanel;
    private JLabel proxyLabel;
    private JCheckBox checkBoxHighlightToken;
    private JComboBox comboBoxHighlightColor;
    private JLabel labelHighlightToken;
    private JLabel labelHighlightColor;
    private JPanel signerPanel;
    private JLabel signerLabel;
    private JCheckBox checkBoxEnableUnknownSignedString;
    private JCheckBox checkBoxEnableDangerousSignedString;
    private JCheckBox checkBoxEnableExpressSignedString;
    private JCheckBox checkBoxEnableOAuthSignedString;
    private JCheckBox checkBoxEnableTornadoSignedString;
    private JCheckBox checkBoxEnableRubySignedString;
    private JCheckBox checkBoxEnableJWT;

    public SettingsView(Window parent, BurpConfig burpConfig, UserInterface userInterface) {
        this.parent = parent;
        ProxyConfig proxyConfig = burpConfig.proxyConfig();
        SignerConfig signerConfig = burpConfig.signerConfig();

        checkBoxHighlightToken.setSelected(proxyConfig.highlightToken());
        checkBoxHighlightToken.addActionListener(e -> {
            comboBoxHighlightColor.setEnabled(checkBoxHighlightToken.isSelected());
            proxyConfig.setHighlightToken(checkBoxHighlightToken.isSelected());
        });

        comboBoxHighlightColor.setModel(new DefaultComboBoxModel<>(HighlightColor.values()));
        comboBoxHighlightColor.setSelectedItem(proxyConfig.highlightColor());
        comboBoxHighlightColor.setEnabled(proxyConfig.highlightToken());
        comboBoxHighlightColor.addActionListener(e -> proxyConfig.setHighlightColor((HighlightColor) comboBoxHighlightColor.getSelectedItem()));

        proxyLabel.setFont(proxyLabel.getFont().deriveFont(BOLD));
        userInterface.applyThemeToComponent(mainPanel);
        comboBoxHighlightColor.setRenderer(new HighlightComboRenderer());

        checkBoxEnableDangerousSignedString.setSelected(signerConfig.isEnabled(Signers.DANGEROUS));
        checkBoxEnableDangerousSignedString.addActionListener(e ->
                signerConfig.toggleEnabled(Signers.DANGEROUS, checkBoxEnableDangerousSignedString.isSelected()));

        checkBoxEnableExpressSignedString.setSelected(signerConfig.isEnabled(Signers.EXPRESS));
        checkBoxEnableExpressSignedString.addActionListener(e ->
                signerConfig.toggleEnabled(Signers.EXPRESS, checkBoxEnableExpressSignedString.isSelected()));

        checkBoxEnableOAuthSignedString.setSelected(signerConfig.isEnabled(Signers.OAUTH));
        checkBoxEnableOAuthSignedString.addActionListener(e ->
                signerConfig.toggleEnabled(Signers.OAUTH, checkBoxEnableOAuthSignedString.isSelected()));

        checkBoxEnableTornadoSignedString.setSelected(signerConfig.isEnabled(Signers.TORNADO));
        checkBoxEnableTornadoSignedString.addActionListener(e ->
                signerConfig.toggleEnabled(Signers.TORNADO, checkBoxEnableTornadoSignedString.isSelected()));

        checkBoxEnableRubySignedString.setSelected(signerConfig.isEnabled(Signers.RUBY));
        checkBoxEnableRubySignedString.addActionListener(e ->
                signerConfig.toggleEnabled(Signers.RUBY, checkBoxEnableRubySignedString.isSelected()));

        checkBoxEnableJWT.setSelected(signerConfig.isEnabled(Signers.JWT));
        checkBoxEnableJWT.addActionListener(e ->
                signerConfig.toggleEnabled(Signers.JWT, checkBoxEnableJWT.isSelected()));

        checkBoxEnableUnknownSignedString.setSelected(signerConfig.isEnabled(Signers.UNKNOWN));
        checkBoxEnableUnknownSignedString.addActionListener(e ->
                signerConfig.toggleEnabled(Signers.UNKNOWN, checkBoxEnableUnknownSignedString.isSelected()));

    }

    private static class HighlightComboRenderer implements ListCellRenderer<HighlightColor> {
        private final ListCellRenderer<Object> renderer = new DefaultListCellRenderer();

        @Override
        public Component getListCellRendererComponent(JList<? extends HighlightColor> list, HighlightColor value, int index, boolean isSelected, boolean cellHasFocus) {
            JLabel label = (JLabel) renderer.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);

            Color background = isSelected ? list.getSelectionBackground() : value.color;
            label.setBackground(background);

            return label;
        }
    }
}
