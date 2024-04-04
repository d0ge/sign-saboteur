package one.d4d.signsaboteur.forms;

import burp.api.montoya.collaborator.CollaboratorPayloadGenerator;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.config.SignerConfig;
import one.d4d.signsaboteur.hexcodearea.HexCodeAreaFactory;
import one.d4d.signsaboteur.presenter.PresenterStore;
import one.d4d.signsaboteur.rsta.RstaFactory;
import one.d4d.signsaboteur.utils.ErrorLoggingActionListenerFactory;

import java.net.URL;
import java.util.Set;

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
        presenter.setMessage(httpResponse.toByteArray(), targetURL, httpResponse.cookies(), null);
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        Set<MimeType> disabled = Set.of(
                MimeType.IMAGE_UNKNOWN,
                MimeType.IMAGE_BMP,
                MimeType.IMAGE_GIF,
                MimeType.IMAGE_JPEG,
                MimeType.IMAGE_PNG,
                MimeType.IMAGE_SVG_XML,
                MimeType.IMAGE_TIFF,
                MimeType.SCRIPT,
                MimeType.CSS,
                MimeType.SOUND,
                MimeType.VIDEO
                );
        ByteArray content = ByteArray.byteArray("");
        MimeType type = requestResponse.response().statedMimeType();
        if (!disabled.contains(type)) {
            content = requestResponse.response().toByteArray();
        }
        return presenter.isEnabled(content, requestResponse.response().cookies(), null);
    }

    @Override
    public HttpResponse getResponse() {
        return FACTORY.httpResponse(presenter.getMessage());
    }
}
