package burp.scanner;

import one.d4d.signsaboteur.keys.SecretKey;
import one.d4d.signsaboteur.presenter.KeyPresenter;
import one.d4d.signsaboteur.presenter.Presenter;
import one.d4d.signsaboteur.presenter.PresenterStore;

import java.util.List;
import java.util.Set;

public class ScannerPresenter extends Presenter {
    private final PresenterStore presenters;

    public ScannerPresenter(PresenterStore presenters) {
        this.presenters = presenters;
        presenters.register(this);
    }

    public List<SecretKey> getSigningKeys() {
        KeyPresenter keysPresenter = (KeyPresenter) presenters.get(KeyPresenter.class);
        return keysPresenter.getSigningKeys();
    }
    public Set<String> getSigningSecrets() {
        KeyPresenter keysPresenter = (KeyPresenter) presenters.get(KeyPresenter.class);
        return keysPresenter.getSecrets();
    }
    public Set<String> getSigningSalts() {
        KeyPresenter keysPresenter = (KeyPresenter) presenters.get(KeyPresenter.class);
        return keysPresenter.getSalts();
    }
}
