package burp.config;

import burp.proxy.ProxyConfig;
import com.google.gson.annotations.Expose;

public class BurpConfig {
    private final @Expose ProxyConfig proxyConfig = new ProxyConfig();

    public ProxyConfig proxyConfig() {
        return proxyConfig;
    }

}
