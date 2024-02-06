import one.d4d.sessionless.itsdangerous.Attack;
import one.d4d.sessionless.itsdangerous.BruteForce;
import one.d4d.sessionless.itsdangerous.crypto.DjangoTokenSigner;
import one.d4d.sessionless.itsdangerous.model.DangerousSignedToken;
import one.d4d.sessionless.itsdangerous.model.DjangoSignedToken;
import one.d4d.sessionless.itsdangerous.model.SignedToken;
import one.d4d.sessionless.itsdangerous.model.SignedTokenObjectFinder;
import one.d4d.sessionless.keys.SecretKey;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.*;

public class DjangoTest {

    @Test
    void DjangoBruteForceTest() {
        final Set<String> signingSecrets = new HashSet<>(List.of("secret"));
        final Set<String> signingSalts = new HashSet<>(List.of("django.contrib.sessions.backends.signed_cookies"));
        List<SecretKey> knownKeys = new ArrayList<>();
        Attack mode = Attack.Deep;
        String value = "gAWVMwAAAAAAAAB9lIwKdGVzdGNvb2tpZZSMBXBvc2l4lIwGc3lzdGVtlJOUjAhzbGVlcCAzMJSFlFKUcy4:1rBDnz:6RroyItcbm4P82lx2kEAuV2ykxs";
        Optional<SignedToken> optionalToken = SignedTokenObjectFinder.parseToken(value);
        if (optionalToken.isPresent()) {
            DangerousSignedToken token = (DangerousSignedToken) optionalToken.get();
            BruteForce bf = new BruteForce(signingSecrets, signingSalts, knownKeys, mode, token);
            SecretKey k = bf.parallel();
            Assertions.assertNotNull(k);
        } else {
            Assertions.fail("Token not found.");
        }

    }

    @Test
    void DjangoParserTest() {
        byte[] secret = "secret".getBytes();
        byte[] salt = "django.contrib.sessions.backends.signed_cookies".getBytes();
        byte[] sep = new byte[]{(byte) ':'};
        String value = ".eJxTKkstqlSgIpGTn5eukJyfV5KaV6IEAJM1I3A:1rBGj6:xBAP3gQxgLfArMsY2j3SWmpxlqY";
        Optional<SignedToken> optionalToken = SignedTokenObjectFinder.parseToken(value);
        if (optionalToken.isPresent()) {
            DjangoSignedToken token = (DjangoSignedToken) optionalToken.get();
            DjangoTokenSigner s = new DjangoTokenSigner(secret, salt, sep);
            token.setSigner(s);
            Assertions.assertDoesNotThrow(() -> {
                s.unsign(value.getBytes());
            });
        } else {
            Assertions.fail("Token not found.");
        }
    }

    @Test
    void DjangoSignerTest() {
        byte[] secret = "secret".getBytes();
        byte[] salt = "django.contrib.sessions.backends.signed_cookies".getBytes();
        byte[] sep = new byte[]{(byte) ':'};
        String value = "gAWVMwAAAAAAAAB9lIwKdGVzdGNvb2tpZZSMBXBvc2l4lIwGc3lzdGVtlJOUjAhzbGVlcCAzMJSFlFKUcy4:1rBDnz:6RroyItcbm4P82lx2kEAuV2ykxs";
        Optional<SignedToken> optionalToken = SignedTokenObjectFinder.parseToken(value);
        if (optionalToken.isPresent()) {
            DjangoSignedToken token = (DjangoSignedToken) optionalToken.get();
            DjangoTokenSigner s = new DjangoTokenSigner(secret, salt, sep);
            token.setSigner(s);
            Assertions.assertDoesNotThrow(() -> {
                s.unsign(value.getBytes());
            });
        } else {
            Assertions.fail("Token not found.");
        }

    }
}
