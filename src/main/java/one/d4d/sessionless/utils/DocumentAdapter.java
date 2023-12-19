package one.d4d.sessionless.utils;

import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

public class DocumentAdapter implements DocumentListener {

    @FunctionalInterface
    public interface DocumentAction {
        void documentUpdated(DocumentEvent e);
    }

    private final DocumentAction action;

    public DocumentAdapter(DocumentAction action) {
        this.action = action;
    }

    @Override
    public void insertUpdate(DocumentEvent e) {
        action.documentUpdated(e);
    }

    @Override
    public void removeUpdate(DocumentEvent e) {
        action.documentUpdated(e);
    }

    @Override
    public void changedUpdate(DocumentEvent e) {
        action.documentUpdated(e);
    }
}
