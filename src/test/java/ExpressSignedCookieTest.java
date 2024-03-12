import burp.api.montoya.http.message.Cookie;
import one.d4d.sessionless.itsdangerous.Attack;
import one.d4d.sessionless.itsdangerous.BruteForce;
import one.d4d.sessionless.itsdangerous.crypto.ExpressTokenSigner;
import one.d4d.sessionless.itsdangerous.model.ExpressSignedToken;
import one.d4d.sessionless.itsdangerous.model.MutableSignedToken;
import one.d4d.sessionless.itsdangerous.model.SignedTokenObjectFinder;
import one.d4d.sessionless.keys.SecretKey;
import one.d4d.sessionless.utils.TestCookie;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.*;

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
            Optional<ExpressSignedToken> optionalSignedToken =
                    SignedTokenObjectFinder.parseSignedTokenWithinCookies(cookies)
                            .stream()
                            .map(MutableSignedToken::getModified)
                            .map(ExpressSignedToken.class::cast)
                            .findFirst();
            if (optionalSignedToken.isPresent()) {
                ExpressSignedToken token = optionalSignedToken.get();
                token.setSigner(s);
                token.unsign();
                final Set<String> secrets = new HashSet<>(List.of("key1"));
                final Set<String> salts = new HashSet<>(List.of("salt"));
                final List<SecretKey> knownKeys = new ArrayList<>();

                BruteForce bf = new BruteForce(secrets, salts, knownKeys, Attack.Balanced, token);
                SecretKey sk = bf.parallel();
                Assertions.assertNotNull(sk);
            } else throw new Exception("Missed cookie");
        });
    }
}
