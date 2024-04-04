package burp.config;

import one.d4d.signsaboteur.keys.SecretKey;

public interface KeysModelListener {
    void notifyKeyInserted(SecretKey key);

    void notifyKeyDeleted(int rowIndex);

    class InertKeyModelListener implements KeysModelListener {
        @Override
        public void notifyKeyInserted(SecretKey key) {
        }

        @Override
        public void notifyKeyDeleted(int rowIndex) {
        }
    }
}
