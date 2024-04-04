package one.d4d.signsaboteur.presenter;

import java.util.HashMap;
import java.util.Map;

public class PresenterStore {

    private final Map<Class, Presenter> presenters = new HashMap<>();

    public Presenter get(Class cls) {
        return presenters.get(cls);
    }

    public void register(Presenter presenter) {
        presenters.put(presenter.getClass(), presenter);
    }
}
