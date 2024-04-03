package one.d4d.sessionless.presenter;

import burp.config.BurpKeysModelPersistence;
import burp.config.KeysModel;
import burp.config.KeysModelListener;
import com.google.gson.Gson;
import one.d4d.sessionless.forms.WordlistView;
import one.d4d.sessionless.forms.dialog.KeyDialog;
import one.d4d.sessionless.forms.dialog.NewKeyDialog;
import one.d4d.sessionless.forms.dialog.NewWordDialog;
import one.d4d.sessionless.keys.SecretKey;
import one.d4d.sessionless.utils.Utils;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static one.d4d.sessionless.utils.Utils.prettyPrintJSON;

public class KeyPresenter extends Presenter {
    private final KeysModel model;
    private final PresenterStore presenters;
    private final WordlistView view;
    private final DefaultListModel<String> modelSecrets;
    private final DefaultListModel<String> modelSalts;
    private final BurpKeysModelPersistence keysModelPersistence;

    public KeyPresenter(WordlistView view, PresenterStore presenters, KeysModel model, BurpKeysModelPersistence keysModelPersistence, DefaultListModel<String> modelSecrets, DefaultListModel<String> modelSalts) {
        this.view = view;
        this.presenters = presenters;
        this.model = model;
        this.keysModelPersistence = keysModelPersistence;
        this.modelSecrets = modelSecrets;
        this.modelSalts = modelSalts;

        model.addKeyModelListener(new KeysModelListener() {
            @Override
            public void notifyKeyInserted(SecretKey key) {
                view.addKey(key);
                keysModelPersistence.save(model);
            }

            @Override
            public void notifyKeyDeleted(int rowIndex) {
                view.deleteKey(rowIndex);
                keysModelPersistence.save(model);
            }
        });
        presenters.register(this);
    }

    public void onButtonLoadSecretsClick(ActionEvent e) {
        readSecretsFromFile(e);
    }

    public void onButtonAddSecretsClick(ActionEvent e) {
        NewWordDialog d = new NewWordDialog(view.getParent());
        d.display();

        // If the dialog returned an item, add it to the model
        String item = d.getItem();
        if (item != null) {
            model.addSecret(item);
            modelSecrets.addElement(item);
        }
    }

    public void onButtonRemoveSecretsClick(ActionEvent e) {
        JList listSecrets = view.getSecretsList();
        ListSelectionModel selmodel = listSecrets.getSelectionModel();
        int index = selmodel.getMinSelectionIndex();

        if (index >= 0) {
            String s = modelSecrets.get(index);
            modelSecrets.remove(index);
            model.removeSecret(s);
        }
    }

    public void onButtonCleanSecretsClick(ActionEvent e) {
        modelSecrets.clear();
        model.clearSecrets();
        view.getSecretsTextArea().setText("");
    }

    public void onButtonLoadSaltsClick(ActionEvent e) {
        readSaltsFromFile(e);
    }

    public void onButtonAddSaltsClick(ActionEvent e) {

        NewWordDialog d = new NewWordDialog(view.getParent());
        d.display();

        // If the dialog returned an item, add it to the model
        String item = d.getItem();
        if (item != null) {
            model.addSalt(item);
            modelSalts.addElement(item);
        }
    }

    public void onButtonRemoveSaltsClick(ActionEvent e) {
        JList listSalts = view.getSaltsList();
        ListSelectionModel selmodel = listSalts.getSelectionModel();
        int index = selmodel.getMinSelectionIndex();

        if (index >= 0) {
            String s = modelSalts.get(index);
            modelSalts.remove(index);
            model.removeSalt(s);
        }
    }

    public void onButtonCleanSaltsClick(ActionEvent e) {
        modelSalts.clear();
        model.clearSalts();
        view.getSaltsTextArea().setText("");
    }

    public void onButtonNewSecretKeyClick() {
        KeyDialog d = new NewKeyDialog(view.getParent(), presenters);
        d.display();

        // If the dialog returned a key, add it to the model
        if (d.getKey() != null) {
            model.addKey((SecretKey) d.getKey());
        }
    }

    public void onButtonLoadDefaultsClick() {
        Utils.readDefaultSecretKeys("/keys", this.getClass()).forEach(model::addKey);
    }

    public void onTableKeysDoubleClick() {
        SecretKey key = model.getKey(view.getSelectedRow());

        KeyDialog d;

        // Get the dialog type based on the key type
        if (key != null) {
            d = new NewKeyDialog(view.getParent(), presenters, key);
        } else {
            return;
        }

        d.display();

        // If dialog returned a key, replace the key in the store with the new key
        SecretKey newKey = (SecretKey) d.getKey();
        if (newKey != null) {
            model.deleteKey(key);
            model.addKey(newKey);
        }
    }

    public void onPopupDelete(int[] rows) {
        String messageResourceId = rows.length > 1 ? "keys_confirm_delete_multiple" : "keys_confirm_delete_single";

        int option = JOptionPane.showConfirmDialog(
                view.getParent(),
                Utils.getResourceString(messageResourceId),
                Utils.getResourceString("keys_confirm_delete_title"),
                JOptionPane.YES_NO_OPTION
        );

        if (option == JOptionPane.OK_OPTION) {
            model.deleteKeys(rows);
        }
    }

    public void onPopupCopy(int row) {
        SecretKey key = model.getKey(row);
        Utils.copyToClipboard(prettyPrintJSON(key.toJSONString()));
    }

    private void readSecretsFromFile(ActionEvent e) {
        JFileChooser fc = new JFileChooser();
        int returnVal = fc.showOpenDialog(view.getUiComponent());
        if (returnVal == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fc.getSelectedFile();
            Set<String> s = Utils.deserializeFile(selectedFile);
            if (!s.isEmpty()) {
                model.setSecrets(s);
                model.setSecretsFilePath(selectedFile.getAbsolutePath());
                modelSecrets.clear();
                modelSecrets.addAll(s);
                view.getSecretsTextArea().setText(selectedFile.getAbsolutePath());
                keysModelPersistence.save(model);
            }
        }
    }

    private void readSaltsFromFile(ActionEvent e) {
        JFileChooser fc = new JFileChooser();
        int returnVal = fc.showOpenDialog(view.getUiComponent());
        if (returnVal == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fc.getSelectedFile();
            Set<String> s = Utils.deserializeFile(selectedFile);
            if (!s.isEmpty()) {
                model.setSalts(s);
                model.setSaltsFilePath(selectedFile.getAbsolutePath());
                modelSalts.clear();
                modelSalts.addAll(s);
                view.getSaltsTextArea().setText(selectedFile.getAbsolutePath());
                keysModelPersistence.save(model);
            }
        }
    }

    public Set<String> getSecrets() {
        return model.getSecrets();
    }

    public Set<String> getSalts() {
        return model.getSalts();
    }

    public boolean keyExists(String keyId) {
        return model.getKey(keyId).isPresent();
    }

    public void addKey(SecretKey key) {
        model.addKey(key);
    }

    public List<SecretKey> getSigningKeys() {
        return model.getSigningKeys();
    }
}
