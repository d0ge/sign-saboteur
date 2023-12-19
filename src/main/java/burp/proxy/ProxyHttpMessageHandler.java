package burp.proxy;

import burp.api.montoya.proxy.http.*;
import burp.api.montoya.utilities.ByteUtils;

public class ProxyHttpMessageHandler implements ProxyRequestHandler, ProxyResponseHandler {
    private final AnnotationsModifier annotationsModifier;

    public ProxyHttpMessageHandler(ProxyConfig proxyConfig, ByteUtils byteUtils) {
        this.annotationsModifier = new AnnotationsModifier(proxyConfig, byteUtils);
    }

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
        annotationsModifier.updateAnnotationsIfApplicable(
                interceptedRequest.annotations(),
                interceptedRequest.toByteArray(),
                null,
                interceptedRequest.parameters());

        return ProxyRequestReceivedAction.continueWith(interceptedRequest);
    }

    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
        return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
    }

    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse interceptedResponse) {
        annotationsModifier.updateAnnotationsIfApplicable(
                interceptedResponse.annotations(),
                interceptedResponse.toByteArray(),
                interceptedResponse.cookies(),
                null);
        return ProxyResponseReceivedAction.continueWith(interceptedResponse);
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse interceptedResponse) {
        return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
    }
}
