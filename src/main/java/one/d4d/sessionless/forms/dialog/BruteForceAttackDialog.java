package one.d4d.sessionless.forms.dialog;

import one.d4d.sessionless.itsdangerous.Attack;
import one.d4d.sessionless.itsdangerous.BruteForce;
import one.d4d.sessionless.itsdangerous.model.SignedToken;
import one.d4d.sessionless.keys.SecretKey;
import one.d4d.sessionless.utils.ErrorLoggingActionListenerFactory;
import one.d4d.sessionless.utils.Utils;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.util.List;
import java.util.Set;


public class BruteForceAttackDialog extends AbstractDialog {
    private JPanel contentPane;
    private JButton buttonCancel;
    private JProgressBar progressBarBruteForce;
    private JLabel lblStatus;
    private SecretKey secretKey;

    public BruteForceAttackDialog(
            Window parent,
            ErrorLoggingActionListenerFactory actionListenerFactory,
            Set<String> signingSecrets,
            Set<String> signingSalts,
            List<SecretKey> signingKeys,
            Attack mode,
            SignedToken token
    ) {
        super(parent, "attack_dialog_title");

        setContentPane(contentPane);
        getRootPane().setDefaultButton(buttonCancel);


        // call onCancel() when cross is clicked
        setDefaultCloseOperation(DO_NOTHING_ON_CLOSE);
        addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent e) {
                onCancel();
            }
        });

        // call onCancel() on ESCAPE
        contentPane.registerKeyboardAction(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                onCancel();
            }
        }, KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);

        // Logic
        String lblText = String.format(
                Utils.getResourceString("attack_dialog_progress_bar_status"),
                mode == Attack.KNOWN ? signingKeys.size() : signingSecrets.size(),
                mode == Attack.KNOWN ? signingKeys.size() : signingSalts.size(),
                mode.getName()
        );
        lblStatus.setText(lblText);
        SwingWorker<Void, Void> sw = new SwingWorker<Void, Void>() {
            private BruteForce bf;

            @Override
            protected Void doInBackground() throws Exception {
                bf = new BruteForce(signingSecrets, signingSalts, signingKeys, mode, token);
                SecretKey k = bf.parallel();
                if (k != null) {
                    secretKey = k;
                }
                return null;
            }

            @Override
            protected void done() {
                if (isCancelled()) {
                    if (bf != null) bf.shutdown();
                }
                dispose();
            }
        };
        sw.execute();
        buttonCancel.addActionListener(e -> {
            sw.cancel(true);
            onCancel();
        });
        this.addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent e) {
                sw.cancel(true);
            }

            public void windowClosed(WindowEvent e) {
                sw.cancel(true);
            }
        });
    }


    private void createUIComponents() {
        progressBarBruteForce = new JProgressBar(0, 100);
        progressBarBruteForce.setIndeterminate(true);
    }


    public SecretKey getSecretKey() {
        return secretKey;
    }

}
