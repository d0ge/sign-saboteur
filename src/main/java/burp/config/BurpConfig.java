package burp.config;

import com.google.gson.annotations.Expose;

public class BurpConfig {
    private final @Expose ProxyConfig proxyConfig = new ProxyConfig();
    private final @Expose SignerConfig signerConfig = new SignerConfig();

    public ProxyConfig proxyConfig() {
        return proxyConfig;
    }

    public SignerConfig signerConfig() {
        return signerConfig;
    }
}
