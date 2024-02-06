package one.d4d.sessionless.forms;

import burp.api.montoya.collaborator.CollaboratorPayloadGenerator;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.config.SignerConfig;
import one.d4d.sessionless.hexcodearea.HexCodeAreaFactory;
import one.d4d.sessionless.presenter.PresenterStore;
import one.d4d.sessionless.rsta.RstaFactory;
import one.d4d.sessionless.utils.ErrorLoggingActionListenerFactory;

import java.net.URL;

import static burp.api.montoya.internal.ObjectFactoryLocator.FACTORY;

public class ResponseEditorView extends EditorTab implements ExtensionProvidedHttpResponseEditor {

    public ResponseEditorView(
            PresenterStore presenters,
            RstaFactory rstaFactory,
            Logging logging,
            UserInterface userInterface,
            CollaboratorPayloadGenerator collaboratorPayloadGenerator,
            SignerConfig signerConfig,
            boolean editable,
            boolean isProVersion) {
        super(
                presenters,
                rstaFactory,
                new HexCodeAreaFactory(logging, userInterface),
                collaboratorPayloadGenerator,
                new ErrorLoggingActionListenerFactory(logging),
                signerConfig,
                editable,
                isProVersion
        );
    }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        HttpResponse httpResponse = requestResponse.response();
        URL targetURL;
        try {
            URL raw = new URL(requestResponse.url());
            targetURL = new URL(raw.getProtocol(),
                    raw.getAuthority(),
                    raw.getPath());
        } catch (Exception e) {
            targetURL = null;
        }
        presenter.setMessage(httpResponse.toByteArray().toString(), targetURL, httpResponse.cookies(), null);
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        MimeType type = requestResponse.response().statedMimeType();
        String content = "";
        if (type == MimeType.HTML || type == MimeType.JSON || type == MimeType.PLAIN_TEXT) {
            content = requestResponse.response().toByteArray().toString();
        }
        return presenter.isEnabled(content, requestResponse.response().cookies(), null);
    }

    @Override
    public HttpResponse getResponse() {
        return FACTORY.httpResponse(presenter.getMessage());
    }
}
