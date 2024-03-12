package one.d4d.sessionless.presenter;

import burp.api.montoya.collaborator.CollaboratorPayloadGenerator;
import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.config.SignerConfig;
import one.d4d.sessionless.forms.EditorTab;
import one.d4d.sessionless.forms.MessageDialogFactory;
import one.d4d.sessionless.forms.dialog.*;
import one.d4d.sessionless.itsdangerous.Attack;
import one.d4d.sessionless.itsdangerous.model.*;
import one.d4d.sessionless.keys.Key;
import one.d4d.sessionless.keys.SecretKey;
import one.d4d.sessionless.utils.ErrorLoggingActionListenerFactory;
import one.d4d.sessionless.utils.Utils;

import java.net.URL;
import java.util.Base64;
import java.util.List;
import java.util.Set;

import static one.d4d.sessionless.itsdangerous.model.SignedTokenObjectFinder.containsSignedTokenObjects;

public class EditorPresenter extends Presenter {
    private final PresenterStore presenters;
    private final SignerConfig signerConfig;
    private final EditorModel model;
    private final EditorTab view;
    private final CollaboratorPayloadGenerator collaboratorPayloadGenerator;
    private final ErrorLoggingActionListenerFactory actionListenerFactory;
    private final MessageDialogFactory messageDialogFactory;
    private boolean selectionChanging;
    private URL targetURL;

    public EditorPresenter(
            EditorTab view,
            CollaboratorPayloadGenerator collaboratorPayloadGenerator,
            ErrorLoggingActionListenerFactory actionListenerFactory,
            PresenterStore presenters,
            SignerConfig signerConfig) {
        this.view = view;
        this.model = new EditorModel(signerConfig);
        this.collaboratorPayloadGenerator = collaboratorPayloadGenerator;
        this.actionListenerFactory = actionListenerFactory;
        this.presenters = presenters;
        messageDialogFactory = new MessageDialogFactory(view.uiComponent());
        presenters.register(this);
        this.signerConfig = signerConfig;
    }

    public void setMessage(String content, URL targetURL, List<Cookie> cookies, List<ParsedHttpParameter> params) {
        this.targetURL = targetURL;
        model.setMessage(content, cookies, params);
        view.setSignedTokenObjects(model.getSerializedObjectStrings());
    }

    private DangerousSignedToken getDangerous() {
        String payload;
        if (view.getDangerouseIsJSON()) {
            String json = Utils.compactJSON(view.getDangerousPayload());
            if (view.getDangerouseIsCompressed()) {
                payload = Utils.compressBase64(json.getBytes());
            } else {
                payload = Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes());
            }
        } else {
            payload = view.getDangerousPayload();
        }
        String timestamp;
        String signature = Base64.getUrlEncoder().withoutPadding().encodeToString(view.getDangerousSignature());
        byte[] separator = view.getDangerousSeparator().length == 0 ? new byte[]{46} : view.getDangerousSeparator();
        if (view.getDangerouseIsDjangoFormatting()) {
            timestamp = Utils.encodeBase62TimestampFromDate(view.getDangerousTimestamp());
            return new DjangoSignedToken(
                    separator,
                    payload,
                    timestamp,
                    signature);
        } else {
            timestamp = Utils.encodeBase64TimestampFromDate(view.getDangerousTimestamp());
            return new DangerousSignedToken(
                    separator,
                    payload,
                    timestamp,
                    signature);
        }

    }

    private void setDangerous(DangerousSignedToken token) {
        view.setDangerouseIsCompressed(token.isCompressed());
        try {
            String payload = new String(Utils.base64Decompress(token.getPayload().getBytes()));
            if (Utils.isValidJSON(payload)) {
                view.setDangerouseIsJSON(true);
                view.setDangerousPayload(Utils.prettyPrintJSON(payload));
            } else {
                view.setDangerouseIsJSON(false);
                view.setDangerousPayload(token.getPayload());
            }
        } catch (Exception e) {
            view.setDangerouseIsJSON(false);
            view.setDangerousPayload(token.getPayload());
        }

        if (token instanceof DjangoSignedToken) {
            view.setDangerouseIsDjangoFormatting(true);
            view.setDangerousTimestamp(token.getTimestamp());
        } else {
            view.setDangerouseIsDjangoFormatting(false);
            view.setDangerousTimestamp(token.getTimestamp());
        }
        view.setDangerousSignature(token.getSignature());
        view.setDangerousSeparator(token.getSeparator());
    }

    private OauthProxySignedToken getOAuth() {
        String parameter = view.getOAuthParameter();
        String payload = view.getOAuthPayload();
        String timestamp = Utils.timestampFromDateInSeconds(view.getOAuthTimestamp());
        String signature = Base64.getUrlEncoder().withoutPadding().encodeToString(view.getOAuthSignature());
        return new OauthProxySignedToken(
                parameter,
                payload,
                timestamp,
                signature);
    }

    private void setOAuth(OauthProxySignedToken token) {
        view.setOAuthParameter(token.getParameter());
        view.setOAuthPayload(token.getPayload());
        view.setOAuthTimestamp(token.getTimestamp());
        view.setOAuthSignature(token.getSignature());
    }

    private ExpressSignedToken getExpress() {
        String parameter = view.getExpressParameter();
        String payload = Base64.getUrlEncoder().encodeToString(view.getExpressPayload().getBytes());
        String signature = view.getExpressSignature();
        return new ExpressSignedToken(parameter, payload, signature);
    }

    private void setExpress(ExpressSignedToken token) {
        view.setExpressPayload(token.getPayload());
        view.setExpressParameter(token.getParameter());
        view.setExpressSignature(new String(token.getSignature()));
    }

    private TornadoSignedToken getTornado() {

        String name = view.getTornadoName();
        String value = Base64.getUrlEncoder().encodeToString(view.getTornadoValue().getBytes());
        String timestamp = Utils.timestampFromDateInSeconds(view.getTornadoTimestamp());
        String signature = new String(view.getTornadoSignature());

        return new TornadoSignedToken(timestamp, name, value, signature);
    }

    private void setTornado(TornadoSignedToken token) {
        view.setTornadoTimestamp(token.getTimestamp());
        view.setTornadoName(token.getName());
        view.setTornadoValue(token.getValue());
        view.setTornadoSignature(token.getSignature());
    }

    private RubySignedToken getRuby() {
        String message = view.getRubyMessage();
        String signature = view.getRubySignature();
        byte[] separator = view.getRubySeparator().length == 0 ? new byte[]{46} : view.getRubySeparator();

        return new RubySignedToken(message, signature, separator);
    }

    private void setRuby(RubySignedToken token) {
        view.setRubyMessage(token.getEncodedMessage());
        view.setRubySignature(token.getEncodedSignature());
        view.setRubySeparator(token.getSeparator());
    }

    private JSONWebSignature getJSONWebSignature() {
        String header = Base64.getUrlEncoder().withoutPadding().encodeToString(view.getJWTHeader().getBytes());
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(view.getJWTPayload().getBytes());
        String signature = Base64.getUrlEncoder().withoutPadding().encodeToString(view.getJWTSignature());
        byte[] separator = view.getJWTSeparator().length == 0 ? new byte[]{46} : view.getJWTSeparator();
        return new JSONWebSignature(header, payload, signature, separator);
    }

    private void setJSONWebSignature(JSONWebSignature token) {
        view.setJWTHeader(token.getHeader());
        view.setJWTPayload(token.getPayload());
        view.setJWTSignature(token.getSignature());
        view.setJWTSeparator(token.getSeparator());
    }

    private UnknownSignedToken getUnknown() {
        String message = view.getUnknownMessage();
        String signature = view.getUnknownSignature();
        byte[] separator = view.getUnknownSeparator().length == 0 ? new byte[]{46} : view.getUnknownSeparator();

        return new UnknownSignedToken(message, signature, separator);
    }

    private void setUnknown(UnknownSignedToken token) {
        view.setUnknownMessage(token.getEncodedMessage());
        view.setUnknownSignature(token.getEncodedSignature());
        view.setUnknownSeparator(token.getSeparator());
    }


    public void componentChanged() {
        MutableSignedToken mutableSignedTokenObject = model.getSignedTokenObject(view.getSelectedSignedTokenObjectIndex());

        SignedToken tokenObject;
        switch (view.getMode()) {
            case EditorTab.TAB_DANGEROUS -> tokenObject = getDangerous();
            case EditorTab.TAB_EXPRESS -> tokenObject = getExpress();
            case EditorTab.TAB_OAUTH -> tokenObject = getOAuth();
            case EditorTab.TAB_TORNADO -> tokenObject = getTornado();
            case EditorTab.TAB_RUBY -> tokenObject = getRuby();
            case EditorTab.TAB_JWT -> tokenObject = getJSONWebSignature();
            default -> tokenObject = getUnknown();
        }
        mutableSignedTokenObject.setModified(tokenObject);
        view.setSignedToken(tokenObject.serialize(), mutableSignedTokenObject.changed() && !selectionChanging);
    }

    public void onSelectionChanged() {
        selectionChanging = true;

        MutableSignedToken mutableJoseObject = model.getSignedTokenObject(view.getSelectedSignedTokenObjectIndex());
        SignedToken tokenObject = mutableJoseObject.getModified();

        if (tokenObject instanceof DangerousSignedToken) {
            view.setDangerousMode();
            setDangerous((DangerousSignedToken) tokenObject);
        } else if (tokenObject instanceof ExpressSignedToken) {
            view.setExpressMode();
            setExpress((ExpressSignedToken) tokenObject);
        } else if (tokenObject instanceof OauthProxySignedToken) {
            view.setOAuthMode();
            setOAuth((OauthProxySignedToken) tokenObject);
        } else if (tokenObject instanceof TornadoSignedToken) {
            view.setTornadoMode();
            setTornado((TornadoSignedToken) tokenObject);
        } else if (tokenObject instanceof RubySignedToken) {
            view.setRubyMode();
            setRuby((RubySignedToken) tokenObject);
        } else if (tokenObject instanceof JSONWebSignature) {
            view.setJWTMode();
            setJSONWebSignature((JSONWebSignature) tokenObject);
        } else if (tokenObject instanceof UnknownSignedToken) {
            view.setUnknownMode();
            setUnknown((UnknownSignedToken) tokenObject);
        }
        selectionChanging = false;
    }

    public void copyExpressSignature() {
        Utils.copyToClipboard(view.getExpressSignature());
    }

    public void onSignClicked() {
        signingDialog();
    }

    public void onAttackClicked() {
        attackDialog();
    }

    private void attackDialog() {
        KeyPresenter keysPresenter = (KeyPresenter) presenters.get(KeyPresenter.class);

        MutableSignedToken mutableJoseObject = model.getSignedTokenObject(view.getSelectedSignedTokenObjectIndex());
        SignedToken tokenObject = mutableJoseObject.getModified();

        if (keysPresenter.getSigningKeys().isEmpty()) {
            messageDialogFactory.showWarningDialog("error_title_no_signing_keys", "error_no_signing_keys");
            return;
        }

        AttackDialog signDialog = new AttackDialog(
                view.window(),
                actionListenerFactory,
                keysPresenter.getSigningKeys(),
                targetURL,
                tokenObject
        );
        signDialog.display();

        SignedToken signed = signDialog.getToken();
        if (signed != null) {
            if (signed instanceof DangerousSignedToken) {
                view.setDangerousMode();
                setDangerous((DangerousSignedToken) signed);
            } else if (signed instanceof ExpressSignedToken) {
                view.setExpressMode();
                setExpress((ExpressSignedToken) signed);
            } else if (signed instanceof OauthProxySignedToken) {
                view.setOAuthMode();
                setOAuth((OauthProxySignedToken) signed);
            } else if (signed instanceof TornadoSignedToken) {
                view.setTornadoMode();
                setTornado((TornadoSignedToken) signed);
            } else if (signed instanceof RubySignedToken) {
                view.setRubyMode();
                setRuby((RubySignedToken) signed);
            } else if (signed instanceof JSONWebSignature) {
                view.setJWTMode();
                setJSONWebSignature((JSONWebSignature) signed);
            } else if (signed instanceof UnknownSignedToken) {
                view.setUnknownMode();
                setUnknown((UnknownSignedToken) signed);
            }
        }
    }

    private void signingDialog() {
        KeyPresenter keysPresenter = (KeyPresenter) presenters.get(KeyPresenter.class);

        MutableSignedToken mutableJoseObject = model.getSignedTokenObject(view.getSelectedSignedTokenObjectIndex());
        SignedToken tokenObject = mutableJoseObject.getModified();

        if (keysPresenter.getSigningKeys().size() == 0) {
            messageDialogFactory.showWarningDialog("error_title_no_signing_keys", "error_no_signing_keys");
            return;
        }

        SignDialog signDialog = new SignDialog(
                view.window(),
                actionListenerFactory,
                keysPresenter.getSigningKeys(),
                tokenObject
        );
        signDialog.display();

        SignedToken signed = signDialog.getToken();
        if (signed != null) {
            if (signed instanceof DangerousSignedToken) {
                view.setDangerousMode();
                setDangerous((DangerousSignedToken) signed);
            } else if (signed instanceof ExpressSignedToken) {
                view.setExpressMode();
                setExpress((ExpressSignedToken) signed);
            } else if (signed instanceof OauthProxySignedToken) {
                view.setOAuthMode();
                setOAuth((OauthProxySignedToken) signed);
            } else if (signed instanceof TornadoSignedToken) {
                view.setTornadoMode();
                setTornado((TornadoSignedToken) signed);
            } else if (signed instanceof RubySignedToken) {
                view.setRubyMode();
                setRuby((RubySignedToken) signed);
            } else if (signed instanceof JSONWebSignature) {
                view.setJWTMode();
                setJSONWebSignature((JSONWebSignature) signed);
            } else if (signed instanceof UnknownSignedToken) {
                view.setUnknownMode();
                setUnknown((UnknownSignedToken) signed);
            }
        }
    }

    public void onAttackClicked(Attack mode) {
        KeyPresenter keysPresenter = (KeyPresenter) presenters.get(KeyPresenter.class);

        MutableSignedToken mutableJoseObject = model.getSignedTokenObject(view.getSelectedSignedTokenObjectIndex());
        SignedToken tokenObject = mutableJoseObject.getModified();

        Set<String> attackKeys = keysPresenter.getSecrets();
        Set<String> attackSalts = keysPresenter.getSalts();

        if (attackKeys.isEmpty()) {
            messageDialogFactory.showWarningDialog("error_title_no_secrets", "error_no_secrets");
            return;
        }

        if (attackSalts.isEmpty()) {
            messageDialogFactory.showWarningDialog("error_title_no_salts", "error_no_salts");
            return;
        }

        if (keysPresenter.getSigningKeys().isEmpty() && mode == Attack.KNOWN) {
            messageDialogFactory.showWarningDialog("error_title_no_signing_keys", "error_no_signing_keys");
            return;
        }

        BruteForceAttackDialog bruteForceDialog = new BruteForceAttackDialog(
                view.window(),
                actionListenerFactory,
                attackKeys,
                attackSalts,
                keysPresenter.getSigningKeys(),
                mode,
                tokenObject);
        bruteForceDialog.display();

        SecretKey k = bruteForceDialog.getSecretKey();

        if (k != null) {
            KeyDialog d;
            d = new NewKeyDialog(view.window(), presenters, k);
            d.display();
            Key newKey = d.getKey();
            if (newKey != null) {
                keysPresenter.addKey((SecretKey) newKey);
            }

        }
    }

    public void onAttackKnownKeysClicked() {
        onAttackClicked(Attack.KNOWN);
    }

    public void onAttackFastClicked() {
        onAttackClicked(Attack.FAST);
    }

    public void onAttackBalancedClicked() {
        onAttackClicked(Attack.Balanced);
    }

    public void onAttackDeepClicked() {
        onAttackClicked(Attack.Deep);
    }

    public boolean isEnabled(String text, List<Cookie> cookies, List<ParsedHttpParameter> params) {
        return containsSignedTokenObjects(signerConfig, text, cookies, params);
    }

    public String getMessage() {
        return model.getMessage();
    }

    public boolean isModified() {
        return model.isModified();
    }
}
