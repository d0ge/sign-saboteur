package burp.config;

import com.google.gson.annotations.Expose;
import one.d4d.sessionless.keys.SecretKey;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.IntStream;

public class KeysModel {
    private final Object lock;
    @Expose
    private final List<SecretKey> keys = new ArrayList<>();
    private List<String> secrets = new ArrayList<>();
    private List<String> salts = new ArrayList<>();
    @Expose
    private String secretsFilePath;
    @Expose
    private String saltsFilePath;
    private KeysModelListener modelListener;

    public KeysModel() {
        this.modelListener = new KeysModelListener.InertKeyModelListener();
        this.lock = new Object();
    }

    public List<String> getSecrets() {
        return secrets;
    }

    public void setSecrets(List<String> secrets) {
        this.secrets = secrets;
    }

    public List<String> getSalts() {
        return salts;
    }

    public void setSalts(List<String> salts) {
        this.salts = salts;
    }

    public String getSecretsFilePath() {
        return secretsFilePath;
    }

    public void setSecretsFilePath(String secretsFilePath) {
        this.secretsFilePath = secretsFilePath;
    }

    public String getSaltsFilePath() {
        return saltsFilePath;
    }

    public void setSaltsFilePath(String saltsFilePath) {
        this.saltsFilePath = saltsFilePath;
    }

    public void clearSecrets() {
        secrets.clear();
    }

    public void clearSalts() {
        salts.clear();
    }

    public void removeSecret(String s) {
        secrets.remove(s);
    }

    public void removeSalt(String s) {
        salts.remove(s);
    }

    public Optional<SecretKey> getKey(String keyId) {
        return keys.stream().filter(x -> keyId.equals(x.getID())).findFirst();
    }

    public SecretKey getKey(int index) {
        synchronized (lock) {
            return keys.get(index);
        }
    }

    public void addKey(SecretKey key) {
        synchronized (lock) {
            keys.add(key);
        }
        modelListener.notifyKeyInserted(key);
    }

    public List<SecretKey> getSigningKeys() {
        synchronized (lock) {
            return keys;
        }
    }

    public void addKeyModelListener(KeysModelListener modelListener) {
        this.modelListener = modelListener;
    }

    public void deleteKey(SecretKey keyId) {
        int rowIndex;

        synchronized (lock) {
            rowIndex = keys.indexOf(keyId);
            keys.remove(keyId);
        }

        if (rowIndex >= 0) {
            modelListener.notifyKeyDeleted(rowIndex);
        }
    }

    public void deleteKeys(int[] indices) {
        synchronized (lock) {
            List<SecretKey> idsToDelete = IntStream.of(indices).mapToObj(this::getKey).toList();

            for (SecretKey id : idsToDelete) {
                deleteKey(id);
            }
        }
    }

}
