package one.d4d.sessionless.forms;

import burp.api.montoya.ui.UserInterface;
import burp.config.BurpConfig;
import burp.config.SignerConfig;
import burp.proxy.HighlightColor;
import burp.config.ProxyConfig;

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

        checkBoxEnableDangerousSignedString.setSelected(signerConfig.isEnableDangerous());
        checkBoxEnableDangerousSignedString.addActionListener(e -> {
            signerConfig.setEnableDangerous(checkBoxEnableDangerousSignedString.isSelected());
        });

        checkBoxEnableExpressSignedString.setSelected(signerConfig.isEnableExpress());
        checkBoxEnableExpressSignedString.addActionListener(e -> {
            signerConfig.setEnableExpress(checkBoxEnableExpressSignedString.isSelected());
        });

        checkBoxEnableOAuthSignedString.setSelected(signerConfig.isEnableOAuth());
        checkBoxEnableOAuthSignedString.addActionListener(e -> {
            signerConfig.setEnableOAuth(checkBoxEnableOAuthSignedString.isSelected());
        });

        checkBoxEnableTornadoSignedString.setSelected(signerConfig.isEnableTornado());
        checkBoxEnableTornadoSignedString.addActionListener(e -> {
            signerConfig.setEnableTornado(checkBoxEnableTornadoSignedString.isSelected());
        });

        checkBoxEnableUnknownSignedString.setSelected(signerConfig.isEnableUnknown());
        checkBoxEnableUnknownSignedString.addActionListener(e -> {
            signerConfig.setEnableUnknown(checkBoxEnableUnknownSignedString.isSelected());
        });
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
