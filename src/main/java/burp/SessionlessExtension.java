package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.Preferences;
import burp.api.montoya.proxy.Proxy;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.utilities.ByteUtils;
import burp.config.*;
import burp.proxy.ProxyHttpMessageHandler;
import burp.proxy.ProxyWsMessageHandler;
import one.d4d.sessionless.forms.ExtensionTab;
import one.d4d.sessionless.forms.RequestEditorView;
import one.d4d.sessionless.forms.ResponseEditorView;
import one.d4d.sessionless.presenter.PresenterStore;
import one.d4d.sessionless.rsta.RstaFactory;
import one.d4d.sessionless.utils.Utils;

import java.awt.*;

import static burp.api.montoya.core.BurpSuiteEdition.PROFESSIONAL;
import static burp.api.montoya.ui.editor.extension.EditorMode.READ_ONLY;

public class SessionlessExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName(Utils.getResourceString("tool_name"));

        Preferences preferences = api.persistence().preferences();
        BurpKeysModelPersistence keysModelPersistence = new BurpKeysModelPersistence(preferences);
        KeysModel keysModel = keysModelPersistence.loadOrCreateNew();

        BurpConfigPersistence burpConfigPersistence = new BurpConfigPersistence(preferences);
        BurpConfig burpConfig = burpConfigPersistence.loadOrCreateNew();
        api.extension().registerUnloadingHandler(() -> burpConfigPersistence.save(burpConfig));

        PresenterStore presenters = new PresenterStore();
        UserInterface userInterface = api.userInterface();
        Window suiteWindow = userInterface.swingUtils().suiteFrame();

        Proxy proxy = api.proxy();
        ProxyConfig proxyConfig = burpConfig.proxyConfig();
        SignerConfig signerConfig = burpConfig.signerConfig();
        ByteUtils byteUtils = api.utilities().byteUtils();

        boolean isProVersion = api.burpSuite().version().edition() == PROFESSIONAL;
        RstaFactory rstaFactory = new RstaFactory(userInterface, api.logging());

        ExtensionTab suiteView = new ExtensionTab(
                suiteWindow,
                presenters,
                keysModel,
                keysModelPersistence,
                burpConfig,
                userInterface
        );

        api.userInterface().registerSuiteTab(suiteView.getTabCaption(), suiteView.getUiComponent());

        userInterface.registerHttpRequestEditorProvider(editorCreationContext ->
                new RequestEditorView(
                        presenters,
                        rstaFactory,
                        api.logging(),
                        api.userInterface(),
                        api.collaborator().defaultPayloadGenerator(),
                        signerConfig,
                        editorCreationContext.editorMode() != READ_ONLY,
                        isProVersion
                )
        );

        userInterface.registerHttpResponseEditorProvider(editorCreationContext ->
                new ResponseEditorView(
                        presenters,
                        rstaFactory,
                        api.logging(),
                        api.userInterface(),
                        api.collaborator().defaultPayloadGenerator(),
                        signerConfig,
                        editorCreationContext.editorMode() != READ_ONLY,
                        isProVersion
                )
        );

        ProxyHttpMessageHandler proxyHttpMessageHandler = new ProxyHttpMessageHandler(proxyConfig, signerConfig, byteUtils);
        proxy.registerRequestHandler(proxyHttpMessageHandler);
        proxy.registerResponseHandler(proxyHttpMessageHandler);

        ProxyWsMessageHandler proxyWsMessageHandler = new ProxyWsMessageHandler(proxyConfig, signerConfig, byteUtils);
        proxy.registerWebSocketCreationHandler(proxyWebSocketCreation ->
                proxyWebSocketCreation.proxyWebSocket().registerProxyMessageHandler(proxyWsMessageHandler)
        );

    }
}
