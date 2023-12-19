package one.d4d.sessionless.utils;

import burp.api.montoya.logging.Logging;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.io.StringWriter;

class ErrorLoggingActionListener implements ActionListener {
    private final Logging logging;
    private final ActionListener actionListener;

    ErrorLoggingActionListener(Logging logging, ActionListener actionListener) {
        this.logging = logging;
        this.actionListener = actionListener;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        try {
            actionListener.actionPerformed(e);
        } catch (RuntimeException ex) {
            StringWriter stackTrace = new StringWriter();
            ex.printStackTrace(new PrintWriter(stackTrace));
            logging.logToError(stackTrace.toString());
        }
    }
}
