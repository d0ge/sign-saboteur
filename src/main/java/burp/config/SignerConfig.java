package burp.config;

import com.google.gson.annotations.Expose;
import one.d4d.sessionless.itsdangerous.crypto.Signers;

import java.util.EnumSet;
import java.util.Set;

public class SignerConfig {

    @Expose
    private Set<Signers> enabled;

    public SignerConfig() {
        EnumSet<Signers> disabled = EnumSet.of(Signers.OAUTH, Signers.NIMBUSDS, Signers.UNKNOWN);
        this.enabled = EnumSet.complementOf(disabled);
    }

    public boolean isEnabled(Signers s) {
        return this.enabled.contains(s);
    }

    public void setEnabled(Signers s) {
        this.enabled.add(s);
    }

    public void removeEnabled(Signers s) {
        this.enabled.remove(s);
    }

    public void toggleEnabled(Signers s, boolean isEnabled) {
        if (isEnabled) {
            this.setEnabled(s);
        } else {
            this.removeEnabled(s);
        }
    }
}
