package burp.config;

import com.google.gson.annotations.Expose;
import one.d4d.signsaboteur.keys.SecretKey;

import java.util.*;
import java.util.stream.IntStream;

public class KeysModel {
    private final Object lockKeys = new Object();
    @Expose
    private final List<SecretKey> keys = new ArrayList<>();
    private Set<String> secrets = new HashSet<>();
    private Set<String> salts = new HashSet<>();
    @Expose
    private String secretsFilePath;
    @Expose
    private String saltsFilePath;
    private KeysModelListener modelListener;

    public KeysModel() {
        this.modelListener = new KeysModelListener.InertKeyModelListener();
    }

    public Set<String> getSecrets() {
        return secrets;
    }

    public void setSecrets(Set<String> secrets) {
        this.secrets.addAll(secrets);
    }

    public Set<String> getSalts() {
        return salts;
    }

    public void setSalts(Set<String> salts) {
        this.salts.addAll(salts);
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

    public void addSecret(String s) {
        secrets.add(s);
    }

    public void removeSalt(String s) {
        salts.remove(s);
    }

    public void addSalt(String s) {
        salts.add(s);
    }

    public Optional<SecretKey> getKey(String keyId) {
        synchronized (lockKeys) {
            return keys.stream().filter(x -> keyId.equals(x.getID())).findFirst();
        }
    }

    public SecretKey getKey(int index) {
        synchronized (lockKeys) {
            return keys.get(index);
        }
    }

    public void addKey(SecretKey key) {
        synchronized (lockKeys) {
            keys.add(key);
        }
        modelListener.notifyKeyInserted(key);
    }

    public List<SecretKey> getSigningKeys() {
        synchronized (lockKeys) {
            return keys;
        }
    }

    public void addKeyModelListener(KeysModelListener modelListener) {
        this.modelListener = modelListener;
    }

    public void deleteKey(SecretKey keyId) {
        int rowIndex;

        synchronized (lockKeys) {
            rowIndex = keys.indexOf(keyId);
            keys.remove(keyId);
        }

        if (rowIndex >= 0) {
            modelListener.notifyKeyDeleted(rowIndex);
        }
    }

    public void deleteKeys(int[] indices) {
        synchronized (lockKeys) {
            List<SecretKey> idsToDelete = IntStream.of(indices).mapToObj(this::getKey).toList();

            for (SecretKey id : idsToDelete) {
                deleteKey(id);
            }
        }
    }

}
