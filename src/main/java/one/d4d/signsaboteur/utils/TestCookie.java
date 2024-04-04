package one.d4d.signsaboteur.utils;

import java.time.ZonedDateTime;
import java.util.Optional;

public class TestCookie implements burp.api.montoya.http.message.Cookie {

    private final String name;
    private final String value;
    private final String domain;
    private final String path;

    public TestCookie(String name, String value, String domain, String path) {
        this.name = name;
        this.value = value;
        this.domain = domain;
        this.path = path;
    }

    @Override
    public String name() {
        return name;
    }

    @Override
    public String value() {
        return value;
    }

    @Override
    public String domain() {
        return domain;
    }

    @Override
    public String path() {
        return path;
    }

    @Override
    public Optional<ZonedDateTime> expiration() {
        return Optional.empty();
    }
}
