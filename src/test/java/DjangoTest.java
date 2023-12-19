import one.d4d.sessionless.itsdangerous.Algorithms;
import one.d4d.sessionless.itsdangerous.Attack;
import one.d4d.sessionless.itsdangerous.BruteForce;
import one.d4d.sessionless.itsdangerous.Derivation;
import one.d4d.sessionless.itsdangerous.crypto.DjangoTokenSigner;
import one.d4d.sessionless.itsdangerous.model.DangerousSignedToken;
import one.d4d.sessionless.itsdangerous.model.DjangoSignedToken;
import one.d4d.sessionless.itsdangerous.model.SignedToken;
import one.d4d.sessionless.itsdangerous.model.SignedTokenObjectFinder;
import one.d4d.sessionless.keys.SecretKey;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

public class DjangoTest {

    @Test
    void DjangoBruteForceTest() {
        List<String> signingSecrets = List.of("secret");
        List<String> signingSalts = List.of("django.contrib.sessions.backends.signed_cookies");
        Attack mode = Attack.Deep;
        String value = "gAWVMwAAAAAAAAB9lIwKdGVzdGNvb2tpZZSMBXBvc2l4lIwGc3lzdGVtlJOUjAhzbGVlcCAzMJSFlFKUcy4:1rBDnz:6RroyItcbm4P82lx2kEAuV2ykxs";
        Optional<SignedToken> optionalToken = SignedTokenObjectFinder.parseToken(value);
        if (optionalToken.isPresent()) {
            DangerousSignedToken token = (DangerousSignedToken) optionalToken.get();
            BruteForce bf = new BruteForce(signingSecrets, signingSalts, mode, token);
            SecretKey k = bf.search();
            Assertions.assertNotNull(k);
        } else {
            Assertions.fail("Token not found.");
        }

    }

    @Test
    void DjangoParserTest() {
        byte[] secret = "secret".getBytes();
        byte[] salt = "django.contrib.sessions.backends.signed_cookies".getBytes();
        String value = ".eJxTKkstqlSgIpGTn5eukJyfV5KaV6IEAJM1I3A:1rBGj6:xBAP3gQxgLfArMsY2j3SWmpxlqY";
        Optional<SignedToken> optionalToken = SignedTokenObjectFinder.parseToken(value);
        if (optionalToken.isPresent()) {
            DjangoSignedToken token = (DjangoSignedToken) optionalToken.get();
            DjangoTokenSigner s = new DjangoTokenSigner(Algorithms.SHA1, Derivation.DJANGO, secret, salt, (byte) ':');
            token.setSigner(s);
            Assertions.assertDoesNotThrow( ()-> {
                s.unsign(value.getBytes());
            });
        } else {
            Assertions.fail("Token not found.");
        }
    }
}
