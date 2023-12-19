package burp.proxy;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.utilities.ByteUtils;
import one.d4d.sessionless.itsdangerous.model.SignedTokenObjectFinder;

import java.util.List;

class AnnotationsModifier {
    private final ByteUtils byteUtils;
    private final ProxyConfig proxyConfig;

    AnnotationsModifier(ProxyConfig proxyConfig, ByteUtils byteUtils) {
        this.byteUtils = byteUtils;
        this.proxyConfig = proxyConfig;
    }

    void updateAnnotationsIfApplicable(Annotations annotations, ByteArray data, List<Cookie> cookies, List<ParsedHttpParameter> params) {
        String message = byteUtils.convertToString(data.getBytes());
        updateAnnotationsIfApplicable(annotations, message, cookies, params);
    }

    void updateAnnotationsIfApplicable(Annotations annotations, String message, List<Cookie> cookies, List<ParsedHttpParameter> params) {
        updateAnnotations(annotations, message, cookies, params);
    }

    private void updateAnnotations(Annotations annotations, String messageString, List<Cookie> cookies, List<ParsedHttpParameter> params) {
        Counts counts = countExtractedSignedTokenObjects(messageString, cookies, params);

        if (!counts.isZero()) {
            annotations.setHighlightColor(proxyConfig.highlightColor().burpColor);
            annotations.setNotes(counts.comment());
        }
    }

    private Counts countExtractedSignedTokenObjects(String messageString, List<Cookie> cookies, List<ParsedHttpParameter> params) {
        int count = SignedTokenObjectFinder.extractSignedTokenObjects(messageString, cookies, params).size();

        return new Counts(proxyConfig, count);
    }

    private record Counts(ProxyConfig proxyConfig, int count) {
        boolean isZero() {
            return count == 0;
        }

        String comment() {
            return proxyConfig.comment(count);
        }
    }
}
