package one.d4d.sessionless.utils;

import burp.api.montoya.logging.Logging;

import java.awt.event.ActionListener;

public class ErrorLoggingActionListenerFactory {
    private final Logging logging;

    public ErrorLoggingActionListenerFactory(Logging logging) {
        this.logging = logging;
    }

    public ErrorLoggingActionListener from(ActionListener actionListener) {
        return new ErrorLoggingActionListener(logging, actionListener);
    }
}
