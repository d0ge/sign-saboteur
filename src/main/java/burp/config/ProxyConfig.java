package burp.config;

import burp.proxy.HighlightColor;
import com.google.gson.annotations.Expose;
import one.d4d.sessionless.utils.Utils;

import static burp.proxy.HighlightColor.GREEN;

public class ProxyConfig {
    public static final HighlightColor DEFAULT_HIGHLIGHT_COLOR = GREEN;

    private static final String BURP_PROXY_COMMENT_TEMPLATE = Utils.getResourceString("burp_proxy_comment");

    @Expose
    private boolean highlightToken;
    @Expose
    private HighlightColor highlightColor;

    public ProxyConfig() {
        this.highlightToken = true;
        this.highlightColor = DEFAULT_HIGHLIGHT_COLOR;
    }

    public boolean highlightToken() {
        return highlightToken;
    }

    public void setHighlightToken(boolean highlightToken) {
        this.highlightToken = highlightToken;
    }

    public HighlightColor highlightColor() {
        return highlightColor;
    }

    public void setHighlightColor(HighlightColor highlightColor) {
        this.highlightColor = highlightColor == null ? DEFAULT_HIGHLIGHT_COLOR : highlightColor;
    }

    public String comment(int count) {
        return String.format(BURP_PROXY_COMMENT_TEMPLATE, count);
    }
}
