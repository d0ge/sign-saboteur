package burp.config;

import com.google.gson.annotations.Expose;

public class SignerConfig {
    @Expose
    private boolean enableDangerous;
    @Expose
    private boolean enableExpress;
    @Expose
    private boolean enableOAuth;
    @Expose
    private boolean enableTornado;
    @Expose
    private boolean enableUnknown;

    public SignerConfig() {
        this.enableDangerous = true;
        this.enableExpress = true;
        this.enableOAuth = false;
        this.enableTornado = true;
        this.enableUnknown = false;
    }

    public boolean isEnableDangerous() {
        return enableDangerous;
    }

    public void setEnableDangerous(boolean enableDangerous) {
        this.enableDangerous = enableDangerous;
    }

    public boolean isEnableExpress() {
        return enableExpress;
    }

    public void setEnableExpress(boolean enableExpress) {
        this.enableExpress = enableExpress;
    }

    public boolean isEnableOAuth() {
        return enableOAuth;
    }

    public void setEnableOAuth(boolean enableOAuth) {
        this.enableOAuth = enableOAuth;
    }

    public boolean isEnableTornado() {
        return enableTornado;
    }

    public void setEnableTornado(boolean enableTornado) {
        this.enableTornado = enableTornado;
    }

    public boolean isEnableUnknown() {
        return enableUnknown;
    }

    public void setEnableUnknown(boolean enableUnknown) {
        this.enableUnknown = enableUnknown;
    }
}
