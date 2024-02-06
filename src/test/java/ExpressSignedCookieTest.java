import burp.api.montoya.http.message.Cookie;
import one.d4d.sessionless.itsdangerous.crypto.ExpressTokenSigner;
import one.d4d.sessionless.itsdangerous.model.ExpressSignedToken;
import one.d4d.sessionless.itsdangerous.model.MutableSignedToken;
import one.d4d.sessionless.itsdangerous.model.SignedTokenObjectFinder;
import one.d4d.sessionless.utils.TestCookie;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class ExpressSignedCookieTest {
    @Test
    void OauthProxyParserTest() {
        byte[] secret = "key1".getBytes();
        byte[] sep = new byte[]{(byte) '.'};
        ExpressTokenSigner s = new ExpressTokenSigner(secret, sep);

        String payload = "eyJwYXNzcG9ydCI6eyJ1c2VyIjoiYWRtaW4ifSwiZmxhc2giOnt9fQ==";
        String signature = "zNzk1rU-uVc2rF2sGxxkt1t_4ewHRQtuE5OTD8b2FQnMZZV-c1A1eUwV6j4_s2hL";
        TestCookie payloadCookie = new TestCookie("session", payload, "evil.com", "/");
        TestCookie signatureCookie = new TestCookie("session.sig", signature, "evil.com", "/");
        List<Cookie> cookies = new ArrayList<>();
        cookies.add(payloadCookie);
        cookies.add(signatureCookie);
        Assertions.assertDoesNotThrow(() -> {
            Optional<ExpressSignedToken> token =
                    SignedTokenObjectFinder.parseSignedTokenWithinCookies(cookies)
                            .stream()
                            .map(MutableSignedToken::getModified)
                            .map(ExpressSignedToken.class::cast)
                            .findFirst();
            if (token.isPresent()) {
                token.get().setSigner(s);
                token.get().unsign();
            } else throw new Exception("Missed cookie");
        });
    }
}
