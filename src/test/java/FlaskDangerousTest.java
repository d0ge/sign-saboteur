import one.d4d.sessionless.itsdangerous.Algorithms;
import one.d4d.sessionless.itsdangerous.Derivation;
import one.d4d.sessionless.itsdangerous.crypto.DangerousTokenSigner;
import one.d4d.sessionless.itsdangerous.model.DangerousSignedToken;
import one.d4d.sessionless.itsdangerous.model.SignedToken;
import one.d4d.sessionless.itsdangerous.model.SignedTokenObjectFinder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class FlaskDangerousTest {

    @Test
    void DangerousParserTest() {
        byte[] secret = "secret".getBytes();
        byte[] salt = "django.contrib.sessions.backends.signed_cookies".getBytes();
        String value = "gAWVMwAAAAAAAAB9lIwKdGVzdGNvb2tpZZSMBXBvc2l4lIwGc3lzdGVtlJOUjAhzbGVlcCAzMJSFlFKUcy4:1rBDnz:6RroyItcbm4P82lx2kEAuV2ykxs";
        Optional<SignedToken> optionalToken = SignedTokenObjectFinder.parseToken(value);
        if (optionalToken.isPresent()) {
            DangerousSignedToken token = (DangerousSignedToken) optionalToken.get();
            DangerousTokenSigner s = new DangerousTokenSigner(Algorithms.SHA1, Derivation.DJANGO, secret, salt, (byte) ':');
            token.setSigner(s);
            Assertions.assertDoesNotThrow( ()-> {
                s.unsign(value.getBytes());
            });
        } else {
            Assertions.fail("Token not found.");
        }

    }
    @Test
    void DefaultFlaskSignedTokenTest() {
        byte[] secret = "secret".getBytes();
        byte[] salt = "cookie-session".getBytes();
        DangerousSignedToken newToken = new DangerousSignedToken((byte)'.',"{}","Zzx63w","");
        DangerousTokenSigner s = new DangerousTokenSigner(Algorithms.SHA1, Derivation.HMAC,secret,salt,(byte)'.');
        newToken.setSigner(s);
        char[] signedToken = newToken.dumps().toCharArray();
        char[] testValue = "e30.Zzx63w.2BFIyJyE4fVqPm2hhw3edr8QTwo".toCharArray();
        assertArrayEquals(signedToken,testValue);
    }
}
